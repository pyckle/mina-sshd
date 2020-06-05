/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.kex.curve25519;

import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.kex.AbstractDH;
import org.apache.sshd.common.util.security.SecurityUtils;


public class Curve25519SHA256DH extends AbstractDH {

    private final byte q_c[] = new byte[32]; //client's ephemeral public key octet string
    private final byte privatekeyforkeyagreement[] = new byte[32];

    public Curve25519SHA256DH() throws Exception {
        super();
        //generate public key and private key for key agreement
        SecurityUtils.getRandomFactory().get().fill(privatekeyforkeyagreement);
    }

    @Override
    public void setF(byte[] bytes) {
        System.arraycopy(bytes, 0, q_c, 0, bytes.length);
    }

    @Override
    protected byte[] calculateE() throws Exception {
        byte[] e = new byte[32];
        Curve25519.keygen(e, null, privatekeyforkeyagreement);
        return e;
    }

    @Override
    protected byte[] calculateK() throws Exception {
        //create shared secret
        byte[] k = new byte[32];
        Curve25519.curve(k, privatekeyforkeyagreement, q_c);
        //The whole 32 bytes need to be converted into a big integer following the network byte order
        return stripLeadingZeroes(k);
    }

    @Override
    public Digest getHash() throws Exception {
        return BuiltinDigests.sha256.create();
    }

}