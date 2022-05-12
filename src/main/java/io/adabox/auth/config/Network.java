package io.adabox.auth.config;

public enum Network {

    TEST_NET("testnet"),
    MAIN_NET("mainnet");

    private final String  value;

    Network(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
