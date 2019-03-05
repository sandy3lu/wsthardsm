package com.yunjingit.common.crypto;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


public class TokenContextPool {


    protected Set<TokenContext> objects;

    public TokenContextPool(int deviceCount, int pipeCount) {

        objects = new HashSet<TokenContext>(deviceCount * pipeCount);
        for (int i = 0; i < deviceCount; i++) {
            for (int j = 0; j < pipeCount; j++) {
                objects.add(new TokenContext(i, j));
            }
        }
    }


    public synchronized TokenContext getObject() {

        if (objects == null) {
            return null;
        }

        TokenContext conn = findFreeObject();
        // 如果目前没有可以使用的对象，即所有的对象都在使用中
        while (conn == null) {
            conn = findFreeObject();
        }

        return conn;

    }


    /**
     * 查找对象池中所有的对象，查找一个可用的对象，        * 如果没有可用的对象，返回 null
     */
    private TokenContext findFreeObject() {

        TokenContext pObj = null;
        Iterator<TokenContext> enumerate = objects.iterator();
        // 遍历所有的对象，看是否有可用的对象
        while (enumerate.hasNext()) {
            pObj = enumerate.next();
            // 如果此对象不忙，则获得它的对象并把它设为忙
            if (!pObj.isBusy()) {
                pObj.setBusy(true);
            }
            return pObj;
        }
        return null;
    }


    /**
     * 此函数返回一个对象到对象池中，并把此对象置为空闲。        * 所有使用对象池获得的对象均应在不使用此对象时返回它。
     */
    public void returnObject(TokenContext obj) {
        obj.setBusy(false);
        return;
    }

}