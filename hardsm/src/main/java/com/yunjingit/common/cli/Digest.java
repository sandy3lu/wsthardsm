package com.yunjingit.common.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import com.yunjingit.common.HardSM;
import com.yunjingit.common.SMException;

public class Digest implements Command {
    public static final String NAME = "digest";
    public final Opts opts = new Opts();
    public final Options options;
    private HardSM hardSM;

    public Digest() {
        this.options = new Options();
        this.options.addOption(this.opts.help);
        this.options.addOption(this.opts.data);
    }

    public Digest(HardSM hardSM) {
        this();
        this.hardSM = hardSM;
    }

    @Override
    public void execute(String[] args) throws ParseException, SMException {
        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine = parser.parse(this.options, args);

        String data = commandLine.getOptionValue(this.opts.data.getOpt());
        if (null == data || data.length() <= 0) {
            System.out.println("error: data missing");
        } else {
            System.out.println(this.hardSM.apiDigest(0, 0, data.getBytes()));
        }
    }

    @Override
    public void help() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(NAME, this.options);
    }
}
