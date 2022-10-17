/*  
 *  Written by dgo-berlin
 *  This is free and unencumbered software released into the public domain.
 *  
 *  Anyone is free to copy, modify, publish, use, compile, sell, or
 *  distribute this software, either in source code form or as a compiled
 *  binary, for any purpose, commercial or non-commercial, and by any
 *  means.
 *  
 *  In jurisdictions that recognize copyright laws, the author or authors
 *  of this software dedicate any and all copyright interest in the
 *  software to the public domain. We make this dedication for the benefit
 *  of the public at large and to the detriment of our heirs and
 *  successors. We intend this dedication to be an overt act of
 *  relinquishment in perpetuity of all present and future rights to this
 *  software under copyright law.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 *  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *  OTHER DEALINGS IN THE SOFTWARE. 
 */
package org.bitcoin.detection;

import com.williballenthin.rejistry.RegistryHiveFile;
import com.williballenthin.rejistry.RegistryParseException;
import com.williballenthin.rejistry.record.NKRecord;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestModule;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.SQLiteTableReader;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestMessage;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.AnalysisResult;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Score;
import org.sqlite.JDBC;

class BitcoinDataSourceIngestModule implements DataSourceIngestModule {
    //config
    private final boolean checkElectrum;
    private final boolean checkLedgerLive;
    private final boolean checkHwWallets;
    private final boolean checkPaperWallets;
    
    private IngestJobContext context = null;
    private final Blackboard blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard();
    private static final Logger logger = Logger.getLogger(BitcoinIngestModuleFactory.getModuleName());
    
    
    private static final String FILES_ELECTRUM_EXE_N = "electrum-%.exe";
    private static final String FILES_ELECTRUM_EXE_P = "Electrum";
    private static final String FILES_ELECTRUM_WALLET_N = "default_wallet";
    private static final String FILES_ELECTRUM_WALLET_P = "wallets";
    private static final String FILES_ELECTRUM_PORTABLE_N = "%";
    private static final String FILES_ELECTRUM_PORTABLE_P = "electrum_data";
    private static final String FILES_LEDGER_EXE_N = "Ledger%Live.exe";
    private static final String FILES_LEDGER_EXE_P = "Ledger%Live";
    private static final String FILES_LEDGER_UPDATER_N = "installer.exe";
    private static final String FILES_LEDGER_UPDATER_P = "ledger-live-desktop-updater";
    private static final String FILES_LEDGER_WALLET_N = "app.json";
    private static final String FILES_LEDGER_WALLET_P = "Ledger%Live";
    
    private static final String PREFETCH_NAME_ELECTRUM = "electrum-";
    private static final String PREFETCH_NAME_LEDGER = "ledger live";
    
    private static final String SPOOLER_JOB_N = "%.SHD";
    private static final String SPOOLER_JOB_P = "PRINTERS";
    
    private static final String TOAST_FILE_N = "wpndatabase.db%";
    private static final String TOAST_FILE_P = "Notifications";
   
    
    BitcoinDataSourceIngestModule(BitcoinModuleIngestJobSettings settings) {
        this.checkElectrum = settings.checkElectrum();
        this.checkLedgerLive = settings.checkLedgerLive();
        this.checkHwWallets = settings.checkHwWallets();
        this.checkPaperWallets = settings.checkPaperWallets();
    }
    
    private void log(Level level, String msg){
        logger.logp(level, this.getClass().getName(), "", msg);
    }
    
    private void log(Level level, String msg, Exception ex){
        logger.logp(level, this.getClass().getName(), "", msg, ex);
    }
    
    private void addToBlackboard(AbstractFile file, String category, String conclusion) throws Blackboard.BlackboardException, TskCoreException {
        ArrayList<BlackboardAttribute> attrs = new ArrayList<>();
        attrs.add(new BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
        BitcoinIngestModuleFactory.getModuleName(), category));
        AnalysisResult art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT, Score.SCORE_NOTABLE, conclusion, "", "", attrs).getAnalysisResult();
                
        blackboard.postArtifact(art, BitcoinIngestModuleFactory.getModuleName());
        
        // Post a message to the ingest messages in box.
        String msg = "Added " + file.getName() + ", category: " + category + ", conclusion: " + conclusion;
        IngestMessage message = IngestMessage.createMessage(IngestMessage.MessageType.INFO, BitcoinIngestModuleFactory.getModuleName(), msg);
        
        IngestServices.getInstance().postMessage(message);
    }
    
    private void checkFileLocations(Content ds, FileManager fileManager) throws TskCoreException, Blackboard.BlackboardException{
        String category = "Wallet Software Files";
        String category_wallets = "Wallet Files";
        String conclusion_electrum_exe = "Electrum wallet software executed";
        String conclusion_electrum_inst = "Electrum wallet software installed";
        String conclusion_ledger_exe = "Ledger Live wallet software executed";
        String conclusion_ledger_inst = "Ledger Live wallet software installed";
        
        if(this.checkElectrum){
            //electrum 
            //Program Files (x86)\Electrum
            //Users\IEUser\AppData\Roaming\Electrum
            //Windows\SysWOW64\electrum_data (portable)
            List<AbstractFile> files = fileManager.findFiles(ds,FILES_ELECTRUM_EXE_N , FILES_ELECTRUM_EXE_P);
            if(files != null){
                for (AbstractFile file : files) {
                    addToBlackboard(file, category, conclusion_electrum_inst);
                }
            }
            files = fileManager.findFiles(ds, FILES_ELECTRUM_WALLET_N, FILES_ELECTRUM_WALLET_P);
            if(files != null){
                for (AbstractFile file : files) {
                    addToBlackboard(file, category_wallets, conclusion_electrum_exe);
                }
            }
            files = fileManager.findFiles(ds, FILES_ELECTRUM_PORTABLE_N , FILES_ELECTRUM_PORTABLE_P);
            if(files != null){
                for (AbstractFile file : files) {
                    addToBlackboard(file, category, conclusion_electrum_exe + " (portable)");
                }
            }
        }
        
        if(this.checkLedgerLive){
            //ledger live
            //Program Files\Ledger Live\Ledger Live.exe
            //Users\IEUser\AppData\Roaming\Ledger Live\app.json
            //Users\IEUser\AppData\Local\ledger-live-desktop-updater\installer.exe
            List<AbstractFile> files = fileManager.findFiles(ds, FILES_LEDGER_EXE_N, FILES_LEDGER_EXE_P);
            if(files != null){
                for (AbstractFile file : files) {
                    addToBlackboard(file, category, conclusion_ledger_inst);
                }
            }
            files = fileManager.findFiles(ds, FILES_LEDGER_UPDATER_N , FILES_LEDGER_UPDATER_P);
            if(files != null){
                for (AbstractFile file : files) {
                    addToBlackboard(file, category, conclusion_ledger_inst);
                }
            }
            files = fileManager.findFiles(ds, FILES_LEDGER_WALLET_N, FILES_LEDGER_WALLET_P);
            if(files != null){
                for (AbstractFile file : files) {
                    addToBlackboard(file, category_wallets, conclusion_ledger_exe);
                }
            }
        }
    }
    
    private void checkElectrumNotifications(Content ds, FileManager fileManager) throws TskCoreException, Blackboard.BlackboardException, SQLException, IOException, ClassNotFoundException{
        String category = "Windows Toast Notification";
        String conclusion = "Electrum wallet software executed";
        String tmpDir = Case.getCurrentCase().getTempDirectory();
        String tmpfile;
        
        if(this.checkElectrum){
            //electrum 
            //Users/IEUser/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db
            List<AbstractFile> files = fileManager.findFiles(ds,TOAST_FILE_N ,TOAST_FILE_P);
            if(files != null){
                //wpndatabase.db per user, could be more then one
                String u;
                ArrayList<String> users = new ArrayList<>();
                for (AbstractFile file : files) {
                    //get user name
                    u = file.getParent().getParent().getParent().getParent().getParent().getParent().getName();
                    if(!users.contains(u)){
                        users.add(u);
                    }
                    //get all notifications dbs
                    tmpfile = Paths.get(tmpDir, u + "_" + file.getName()).toString();
                    ContentUtils.writeToFile(file, new File(tmpfile));
                }
                for (String user : users) {
                    tmpfile = Paths.get(tmpDir, user + "_" + TOAST_FILE_N.substring(0, TOAST_FILE_N.length()-1)).toString();
                    //just need to know if not empty
                    if(containsRecord(tmpfile)) {
                        List<AbstractFile> fs = fileManager.findFiles(ds,TOAST_FILE_N.substring(0, TOAST_FILE_N.length()-1),TOAST_FILE_P);
                        if(fs != null){
                            for (AbstractFile f : fs) {
                                if(f.getParent().getParent().getParent().getParent().getParent().getParent().getName().equals(user)){
                                    addToBlackboard(f, category, conclusion);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    private boolean containsRecord(String location) throws SQLException{
        //Class.forName("org.sqlite.JDBC"); -> NoClassDefFoundException
        new JDBC(); //was not able to use lib, so needed to include sources :face_palm:
        Connection con = DriverManager.getConnection("jdbc:sqlite:".concat(location));
        Statement st = con.createStatement();
        ResultSet rs = st.executeQuery("select Payload from Notification where Payload like '%Electrum%'");
        boolean r = rs.next();
        con.close();
        
        return r;
    }
    
    private void checkPrefetchFiles(Content ds, FileManager fileManager) throws TskCoreException, Blackboard.BlackboardException{
        String category = "Windows Prefetch Files";
        String conclusion = "Wallet software executed";
        
        List<AbstractFile> files = fileManager.findFiles(ds, "%.pf", "Prefetch");
        
        if(files != null){
            for (AbstractFile file : files) {
                String name = file.getName().toLowerCase();
                if(this.checkElectrum){
                    if(name.contains(PREFETCH_NAME_ELECTRUM) ){
                        addToBlackboard(file, category, conclusion);
                    } 
                }
                if(this.checkLedgerLive){
                    if(name.contains(PREFETCH_NAME_LEDGER) ){
                        addToBlackboard(file, category, conclusion);
                    }
                }
            }
        }
    }
    
    private void checkForPaperWallets(Content ds, FileManager fileManager) throws TskCoreException, Blackboard.BlackboardException, IOException{
        
        if(this.checkPaperWallets){        
            String category = "Windows Spooler Files";
            String conclusion = "Paper wallet printed";
            String tmpDir = Case.getCurrentCase().getTempDirectory();
            String tmpfile;
            InputStream in;
            //hex{62, 00, 69, 00, 74, 00, 61, 00, 64, 00, 64, 00, 72, 00, 65, 00, 73, 00, 73, 00, 2e, 00, 6f, 00, 72, 00, 67, 00} //bitaddress.org
            int []sig = {98, 00, 105, 00, 116, 00, 97, 00, 100, 00, 100, 00, 114, 00, 101, 00, 115, 00, 115, 00, 46, 00, 111, 00, 114, 00, 103, 00}; 
            byte []b_sig = new byte[sig.length-1];
            int b;

            //PrintJobs,
            List<AbstractFile> files = fileManager.findFiles(ds, SPOOLER_JOB_N, SPOOLER_JOB_P);
            if(files != null){
                for (AbstractFile file : files) {
                    //save file to tmp file
                    tmpfile = Paths.get(tmpDir, file.getId() + ".shd").toString();
                    ContentUtils.writeToFile(file, new File(tmpfile));
                    //open tmpfile
                    in = new FileInputStream(tmpfile);                
                    while ((b = in.read()) != -1) {
                        if(b == sig[0]){
                           in.read(b_sig);
                            for (int i = 0; i < (sig.length-1); i++) {
                                if(b_sig[i] != sig[i+1]){
                                    //mismatch
                                    break;
                                }
                                //match
                                if(i == sig.length-2){
                                    addToBlackboard(file, category, conclusion);
                                    //also add print job raw
                                    String n = file.getName().split(".SHD")[0] + ".SPL";
                                    List<AbstractFile> printfile = fileManager.findFiles(ds, n, SPOOLER_JOB_P);
                                    addToBlackboard(printfile.get(0), category, conclusion);

                                }
                            }
                        }
                    }
                    in.close();
                }
            }
        }
    }
    
    private void checkRegistryEntries(Content ds, FileManager fileManager) throws TskCoreException, Blackboard.BlackboardException, RegistryParseException, IOException{
        String category = "Windows Registry";
        String conclusion_electrum_inst = "Electrum wallet software installed";
        String conclusion_ledger_inst = "Ledger Live wallet software installed";
        
        String tmpDir = Case.getCurrentCase().getTempDirectory();
        String tmpfile;
        
        if(this.checkElectrum){    
            //Electrum
            List<AbstractFile> files = fileManager.findFiles(ds, "ntuser.dat");
            if(files != null){
                for (AbstractFile file : files) {
                    tmpfile = Paths.get(tmpDir, file.getId() + ".ntuser.dat.hive").toString();
                    ContentUtils.writeToFile(file, new File(tmpfile));

                    File f = new File(tmpfile);
                    RegistryHiveFile reg = new RegistryHiveFile(f);

                    //HKCU\Software\Electrum\
                    NKRecord nk = reg.getHeader().getRootNKRecord().getSubkeyList().getSubkey("Software");
                    Iterator<NKRecord> nkit = nk.getSubkeyList().getSubkeys();
                    while (nkit.hasNext()) {
                        NKRecord record = nkit.next();
                        if(record.getName().toLowerCase().contains("electrum")){
                            addToBlackboard(file, category, conclusion_electrum_inst);
                            break;
                        }
                    }
                }
            }
        }
        
        if(this.checkLedgerLive){
            //Ledger Live
            List<AbstractFile> files = fileManager.findFiles(ds, "SOFTWARE", "config");
            if(files != null){
                AbstractFile file = files.get(0);
                tmpfile = Paths.get(tmpDir, file.getId() + ".software.hive").toString();
                ContentUtils.writeToFile(file, new File(tmpfile));

                File f = new File(tmpfile);
                RegistryHiveFile reg = new RegistryHiveFile(f);

                //HKCR\ledgerlive\ aka SOFTWARE\Classes\ledgerlive
                NKRecord nk = reg.getHeader().getRootNKRecord().getSubkeyList().getSubkey("Classes");
                Iterator<NKRecord> nkit = nk.getSubkeyList().getSubkeys();
                while (nkit.hasNext()) {
                    NKRecord record = nkit.next();
                    if(record.getName().toLowerCase().contains("ledgerlive")){
                        addToBlackboard(file, category, conclusion_ledger_inst);
                        break;
                    }
                }
            }
        }
    }
 
    private void checkHardwareWalletConnected(Content ds, FileManager fileManager) throws TskCoreException, Blackboard.BlackboardException, IOException, RegistryParseException{
        if(this.checkHwWallets){
            String category = "Windows Registry";
            String conclusion = "Ledger Nano X connected per ";
            String usb = "USB";
            String blt = "Bluetooth";

            String tmpDir = Case.getCurrentCase().getTempDirectory();
            String tmpfile;

            List<AbstractFile> files = fileManager.findFiles(ds, "SYSTEM", "config");
            if(files != null){
                AbstractFile file = files.get(0);
                tmpfile = Paths.get(tmpDir, file.getId() + ".system.hive").toString();
                ContentUtils.writeToFile(file, new File(tmpfile));

                File f = new File(tmpfile);
                RegistryHiveFile reg = new RegistryHiveFile(f);

                //HKLM\System\CurrentControlSet\Enum\USB\vid_2c97&pid_4011/
                NKRecord nk = reg.getHeader().getRootNKRecord().getSubkeyList().getSubkey("ControlSet001")
                        .getSubkeyList().getSubkey("Enum").getSubkeyList().getSubkey("USB");
                Iterator<NKRecord> nkit = nk.getSubkeyList().getSubkeys();
                while (nkit.hasNext()) {
                    NKRecord record = nkit.next();
                    if(record.getName().toLowerCase().contains("vid_2c97&pid_4011")){
                        addToBlackboard(file, category, conclusion.concat(usb));
                        break;
                    }
                }

                //HKLM\System\CurrentControlSet\Services\DeviceAssociationService\State\Store\BluetoothLE#BluetoothLE48:51:b7:b4:a6:17-de:f1:f3:14:1d:b6
                nk = reg.getHeader().getRootNKRecord().getSubkeyList().getSubkey("ControlSet001")
                        .getSubkeyList().getSubkey("Services").getSubkeyList().getSubkey("DeviceAssociationService")
                        .getSubkeyList().getSubkey("State").getSubkeyList().getSubkey("Store");
                nkit = nk.getSubkeyList().getSubkeys();
                while (nkit.hasNext()) {
                    NKRecord record = nkit.next();
                    if(record.getName().toLowerCase().contains("de:f1:f3:")){  
                        addToBlackboard(file, category, conclusion.concat(blt));
                        break;
                    }
                }
            }
        }
    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;
    }

    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        //only called once!
        
        //set number of work units 
        progressBar.switchToDeterminate(6);
        
        try {
            FileManager fileManager = Case.getCurrentCaseThrows().getServices().getFileManager();
            
            // check if we were cancelled
            if (context.dataSourceIngestIsCancelled()) {
                return IngestModule.ProcessResult.OK;
            }
            
            checkFileLocations(dataSource, fileManager);
            progressBar.progress(1);
            
            // check if we were cancelled
            if (context.dataSourceIngestIsCancelled()) {
                return IngestModule.ProcessResult.OK;
            }
            
            checkElectrumNotifications(dataSource, fileManager);
            progressBar.progress(1);
            
            // check if we were cancelled
            if (context.dataSourceIngestIsCancelled()) {
                return IngestModule.ProcessResult.OK;
            }
            
            checkPrefetchFiles(dataSource, fileManager);
            progressBar.progress(1);
            
            // check if we were cancelled
            if (context.dataSourceIngestIsCancelled()) {
                return IngestModule.ProcessResult.OK;
            }
            
            checkForPaperWallets(dataSource, fileManager);
            progressBar.progress(1);
            
            // check if we were cancelled
            if (context.dataSourceIngestIsCancelled()) {
                return IngestModule.ProcessResult.OK;
            }
            
            checkRegistryEntries(dataSource, fileManager);
            progressBar.progress(1);
            
            // check if we were cancelled
            if (context.dataSourceIngestIsCancelled()) {
                return IngestModule.ProcessResult.OK;
            }
            
            checkHardwareWalletConnected(dataSource, fileManager);
            progressBar.progress(1);
            
            return IngestModule.ProcessResult.OK;

        } catch (TskCoreException | NoCurrentCaseException | Blackboard.BlackboardException | IOException | RegistryParseException | SQLException | ClassNotFoundException ex) {
            log(Level.SEVERE, "Bitcoin usage detection failed", ex);
            return IngestModule.ProcessResult.ERROR;
        } 
    }
    
    @Override
    public void shutDown() {
        // This method is thread-safe with per ingest job reference counted
        // management of shared data.
    }
}
