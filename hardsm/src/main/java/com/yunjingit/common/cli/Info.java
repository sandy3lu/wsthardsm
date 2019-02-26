package com.yunjingit.common.cli;

import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import com.yunjingit.common.HardSM;
import com.yunjingit.common.SMException;

public class Info implements Command {
    public static final String NAME = "info";
    public final Opts opts = new Opts();
    public final Options options;
    private HardSM hardSM;

    public Info() {
        this.options = new Options();
    }

    public Info(HardSM hardSM) {
        this();
        this.hardSM = hardSM;
    }

    @Override
    public void execute(String[] args) throws ParseException, SMException {
        System.out.println(this.hardSM.apiPrintContext(true));
    }

    @Override
    public void help() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(NAME, this.options);
    }
}
