package com.yunjingit.common.crypto;


import java.util.Objects;

public class TokenContext {
    @Override
    public boolean equals(Object o) {
        if (this == o) {return true;}
        if (o == null || getClass() != o.getClass()) {return false;}
        TokenContext that = (TokenContext) o;
        return deviceIndex == that.deviceIndex &&
                pipeIndex == that.pipeIndex;
    }

    @Override
    public int hashCode() {
        return Objects.hash(deviceIndex, pipeIndex);
    }

    public TokenContext(int deviceIndex, int pipeIndex) {
        this.deviceIndex = deviceIndex;
        this.pipeIndex = pipeIndex;
    }

    int deviceIndex;
    int pipeIndex;

    public boolean isBusy() {
        return busy;
    }

    public void setBusy(boolean busy) {
        this.busy = busy;
    }

    boolean busy = false; // 此对象是否正在使用的标志，默认没有正在使用

    public void setDeviceIndex(int deviceIndex) {
        this.deviceIndex = deviceIndex;
    }

    public void setPipeIndex(int pipeIndex) {
        this.pipeIndex = pipeIndex;
    }

    public int getDeviceIndex() {
        return deviceIndex;
    }

    public int getPipeIndex() {
        return pipeIndex;
    }


    @Override
    public String toString() {
        return "TokenContext{" +
                "deviceIndex=" + deviceIndex +
                ", pipeIndex=" + pipeIndex +
                '}';
    }
}
