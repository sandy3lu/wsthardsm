package com.yunjingit.common.cli;

import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import com.yunjingit.common.HardSM;
import com.yunjingit.common.SMException;

public class GenerateKey implements Command {
    public static final String NAME = "genkey";
    public final Opts opts = new Opts();
    public final Options options;
    private HardSM hardSM;

    public GenerateKey() {
        this.options = new Options();
    }

    public GenerateKey(HardSM hardSM) {
        this();
        this.hardSM = hardSM;
    }


    @Override
    public void execute(String[] args) throws  SMException {
        String key = this.hardSM.apiGenerateKey(0, 0);
        System.out.println("key: " + key);
    }

    @Override
    public void help() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(NAME, this.options);
    }
}
