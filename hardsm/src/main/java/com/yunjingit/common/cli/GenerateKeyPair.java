package com.yunjingit.common.cli;

import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import com.yunjingit.common.HardSM;
import com.yunjingit.common.SMException;
import com.yunjingit.common.Sm.KeyPair;

public class GenerateKeyPair implements Command {
    public static final String NAME = "gen-keypair";
    public final Opts opts = new Opts();
    public final Options options;
    private HardSM hardSM;

    public GenerateKeyPair() {
        this.options = new Options();
    }

    public GenerateKeyPair(HardSM hardSM) {
        this();
        this.hardSM = hardSM;
    }


    @Override
    public void execute(String[] args) throws  SMException {
        KeyPair keyPair = this.hardSM.apiGenerateKeyPair(0, 0);
        System.out.println("private key: " + keyPair.getPrivateKey());
        System.out.println("public key: " + keyPair.getPublicKey());
    }

    @Override
    public void help() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(NAME, this.options);
    }
}
