package com.yunjingit.common.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import com.yunjingit.common.HardSM;
import com.yunjingit.common.SMException;

public class Verify implements Command {
    public static final String NAME = "verify";
    public final Opts opts = new Opts();
    public final Options options;
    private HardSM hardSM;

    public Verify() {
        this.options = new Options();
        this.options.addOption(this.opts.help);
        this.options.addOption(this.opts.publicKey);
        this.options.addOption(this.opts.data);
        this.options.addOption(this.opts.signature);
    }

    public Verify(HardSM hardSM) {
        this();
        this.hardSM = hardSM;
    }

    @Override
    public void execute(String[] args) throws ParseException, SMException {
        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine = parser.parse(this.options, args);

        String publicKey = commandLine.getOptionValue(this.opts.publicKey.getOpt());
        if (null == publicKey || publicKey.length() <= 0) {
            System.out.println("error: public key missing");
        }
        String data = commandLine.getOptionValue(this.opts.data.getOpt());
        if (null == data || data.length() <= 0) {
            System.out.println("error: data missing");
        }
        String signature = commandLine.getOptionValue(this.opts.signature.getOpt());
        if (null == signature || signature.length() <= 0) {
            System.out.println("error: signature missing");
        }

        String digest = this.hardSM.apiDigest(0, 0, data.getBytes());
        System.out.println(this.hardSM.apiVerify(0, 0, publicKey, digest, signature));
    }

    @Override
    public void help() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(NAME, this.options);
    }
}
