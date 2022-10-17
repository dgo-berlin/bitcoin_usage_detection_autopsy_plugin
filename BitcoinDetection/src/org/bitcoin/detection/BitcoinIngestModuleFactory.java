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

import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

@ServiceProvider(service = IngestModuleFactory.class) // Sample is discarded at runtime 
public class BitcoinIngestModuleFactory implements IngestModuleFactory {

    private static final String VERSION_NUMBER = "1.0.0";

    static String getModuleName() {
        return "Bitcoin Usage Detection";
    }

    @Override
    public String getModuleDisplayName() {
        return getModuleName();
    }

    @Override
    public String getModuleDescription() {
        return "Module could detect usage of selected wallets (Windows only)";
    }
    
    @Override
    public String getModuleVersionNumber() {
        return VERSION_NUMBER;
    }
    
    @Override
    public boolean hasGlobalSettingsPanel() {
        return false;
    }

    @Override
    public IngestModuleGlobalSettingsPanel getGlobalSettingsPanel() {
        throw new UnsupportedOperationException();
    }

    @Override
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings() {
        return new BitcoinModuleIngestJobSettings();
    }

    @Override
    public boolean hasIngestJobSettingsPanel() {
        return true;
    }

    @Override
    public IngestModuleIngestJobSettingsPanel getIngestJobSettingsPanel(IngestModuleIngestJobSettings settings) {
        if (!(settings instanceof BitcoinModuleIngestJobSettings)) {
            throw new IllegalArgumentException("Expected settings argument to be instanceof SampleModuleIngestJobSettings");
        }
        return new BitcoinIngestModuleIngestJobSettingsPanel((BitcoinModuleIngestJobSettings) settings);
    }

    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return true;
    }

    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings settings) {
        if (!(settings instanceof BitcoinModuleIngestJobSettings)) {
            throw new IllegalArgumentException("Expected settings argument to be instanceof SampleModuleIngestJobSettings");
        }
        return new BitcoinDataSourceIngestModule((BitcoinModuleIngestJobSettings) settings);
    }

    @Override
    public boolean isFileIngestModuleFactory() {
        return false;
    }

    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings settings) {
        return null;
    }
}
