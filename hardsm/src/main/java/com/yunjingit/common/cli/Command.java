package com.yunjingit.common.cli;

import org.apache.commons.cli.ParseException;
import com.yunjingit.common.SMException;

public interface Command {
    void execute(String[] args) throws ParseException, SMException;

    void help();
}
