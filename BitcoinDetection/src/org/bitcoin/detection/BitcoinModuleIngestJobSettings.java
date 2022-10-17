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

import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

public class BitcoinModuleIngestJobSettings implements IngestModuleIngestJobSettings {

    private static final long serialVersionUID = 1L;
    private boolean checkElectrum = true;
    private boolean checkLedgerLive = true;
    private boolean checkHwWallets = true;
    private boolean checkPaperWallets = true;
    
    BitcoinModuleIngestJobSettings() {
    }

    BitcoinModuleIngestJobSettings(boolean checkElectrum, boolean checkLedgerLive, boolean checkHwWallets, boolean checkPaperWallets) {
        this.checkElectrum = checkElectrum;
        this.checkLedgerLive = checkLedgerLive;
        this.checkHwWallets = checkHwWallets;
        this.checkPaperWallets = checkPaperWallets;
    }

    @Override
    public long getVersionNumber() {
        return serialVersionUID;
    }

    boolean checkElectrum() {
        return checkElectrum;
    }

    void setCheckElectrum(boolean checkElectrum) {
        this.checkElectrum = checkElectrum;
    }

    boolean checkLedgerLive() {
        return checkLedgerLive;
    }

    void setCheckLedgerLive(boolean checkLedgerLive) {
        this.checkLedgerLive = checkLedgerLive;
    }

    boolean checkHwWallets() {
        return checkHwWallets;
    }

    void setCheckHwWallets(boolean checkHwWallets) {
        this.checkHwWallets = checkHwWallets;
    }

    boolean checkPaperWallets() {
        return checkPaperWallets;
    }

    void setCheckPaperWallets(boolean checkPaperWallets) {
        this.checkPaperWallets = checkPaperWallets;
    }
}
