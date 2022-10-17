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
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

/**
 * UI component used to make per ingest job settings for sample ingest modules.
 */
@SuppressWarnings("PMD.SingularField") // UI widgets cause lots of false positives
public class BitcoinIngestModuleIngestJobSettingsPanel extends IngestModuleIngestJobSettingsPanel {

    /**
     * Creates new form SampleIngestModuleIngestJobSettings
     */
    public BitcoinIngestModuleIngestJobSettingsPanel(BitcoinModuleIngestJobSettings settings) {
        initComponents();
        customizeComponents(settings);
    }

    private void customizeComponents(BitcoinModuleIngestJobSettings settings) {
        checkElectrum.setSelected(settings.checkElectrum());
        checkLedgerLive.setSelected(settings.checkLedgerLive());
        checkHardwareWallets.setSelected(settings.checkHwWallets());
        checkPaperWallets.setSelected(settings.checkPaperWallets());
    }

    /**
     * Gets the ingest job settings for an ingest module.
     *
     * @return The ingest settings.
     */
    @Override
    public IngestModuleIngestJobSettings getSettings() {
        return new BitcoinModuleIngestJobSettings(checkElectrum.isSelected(),checkLedgerLive.isSelected(), checkHardwareWallets.isSelected(), checkPaperWallets.isSelected());
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        checkElectrum = new javax.swing.JCheckBox();
        checkLedgerLive = new javax.swing.JCheckBox();
        checkHardwareWallets = new javax.swing.JCheckBox();
        checkPaperWallets = new javax.swing.JCheckBox();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();

        org.openide.awt.Mnemonics.setLocalizedText(checkElectrum, org.openide.util.NbBundle.getMessage(BitcoinIngestModuleIngestJobSettingsPanel.class, "BitcoinIngestModuleIngestJobSettingsPanel.checkElectrum.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(checkLedgerLive, org.openide.util.NbBundle.getMessage(BitcoinIngestModuleIngestJobSettingsPanel.class, "BitcoinIngestModuleIngestJobSettingsPanel.checkLedgerLive.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(checkHardwareWallets, org.openide.util.NbBundle.getMessage(BitcoinIngestModuleIngestJobSettingsPanel.class, "BitcoinIngestModuleIngestJobSettingsPanel.checkHardwareWallets.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(checkPaperWallets, org.openide.util.NbBundle.getMessage(BitcoinIngestModuleIngestJobSettingsPanel.class, "BitcoinIngestModuleIngestJobSettingsPanel.checkPaperWallets.text")); // NOI18N

        jLabel1.setFont(new java.awt.Font("sansserif", 1, 14)); // NOI18N
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        org.openide.awt.Mnemonics.setLocalizedText(jLabel1, org.openide.util.NbBundle.getMessage(BitcoinIngestModuleIngestJobSettingsPanel.class, "BitcoinIngestModuleIngestJobSettingsPanel.jLabel1.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(jLabel2, org.openide.util.NbBundle.getMessage(BitcoinIngestModuleIngestJobSettingsPanel.class, "BitcoinIngestModuleIngestJobSettingsPanel.jLabel2.text")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(0, 0, 0)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(checkElectrum, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(checkLedgerLive)
                        .addComponent(checkHardwareWallets)
                        .addComponent(checkPaperWallets))
                    .addComponent(jLabel2)))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jLabel1)
                .addGap(25, 25, 25)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(checkElectrum)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(checkLedgerLive)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(checkHardwareWallets)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(checkPaperWallets)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox checkElectrum;
    private javax.swing.JCheckBox checkHardwareWallets;
    private javax.swing.JCheckBox checkLedgerLive;
    private javax.swing.JCheckBox checkPaperWallets;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    // End of variables declaration//GEN-END:variables
}