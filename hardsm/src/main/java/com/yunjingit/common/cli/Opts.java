package com.yunjingit.common.cli;

import org.apache.commons.cli.Option;

public class Opts {
    public final Option help;
    public final Option data;
    public final Option signature;
    public final Option publicKey;
    public final Option secretKey;
    public final Option password;
    public final Option length;

    public Opts() {
        this.help = new Option("h", "help", false, "print this help message");

        this.data = new Option("d", "data", true, "input source data");
        this.data.setRequired(true);

        this.signature = new Option("s", "signature", true, "signature to be verified");
        this.signature.setRequired(true);

        this.publicKey = new Option("pk", "public-key", true, "public key");
        this.publicKey.setRequired(true);

        this.secretKey = new Option("sk", "secret-key", true, "secret key or private key");
        this.secretKey.setRequired(true);

        this.password = new Option("p", "password", true, "password to login card");
        this.password.setRequired(true);

        this.length = new Option("l", "length", true, "length of data");
        this.length.setRequired(true);
    }
}
