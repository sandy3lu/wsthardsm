package com.yunjingit.common.cli;

import java.util.Arrays;
import org.apache.commons.cli.ParseException;
import com.yunjingit.common.HardSM;
import com.yunjingit.common.HardSMImpl;
import com.yunjingit.common.SMException;

public class Main {
    public static void main(String[] args) throws ParseException, SMException {
        if (args.length < 2) {
            printHelp();
            return;
        }

        String password = args[0];
        String command = args[1];

        args = Arrays.copyOfRange(args, 2, args.length);

        HardSM hardSM = new HardSMImpl();
        hardSM.apiInit();
        hardSM.apiLoginDevice(0, password);

        switch (command) {
            case "help": {
                printHelp();
                break;
            } case "digest": {
                new Digest(hardSM).execute(args);
                break;
            } case "random": {
                new Random(hardSM).execute(args);
                break;
            } case "gen-keypair": {
                new GenerateKeyPair(hardSM).execute(args);
                break;
            } case "sign": {
                new Sign(hardSM).execute(args);
                break;
            } case "verify": {
                new Verify(hardSM).execute(args);
                break;
            } case "info": {
                new Info(hardSM).execute(args);
                break;
            } default: {
                printHelp();
                break;
            }
        }

        hardSM.apiLogoutDevice(0);
        hardSM.apiFinal();
    }

    public static void printHelp() {
        new Digest().help();
        new Random().help();
        new GenerateKeyPair().help();
        new Sign().help();
        new Verify().help();
        new Info().help();
    }
}
