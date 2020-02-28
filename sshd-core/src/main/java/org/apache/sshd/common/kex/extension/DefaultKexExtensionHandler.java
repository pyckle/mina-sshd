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
package org.apache.sshd.common.kex.extension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.extension.parser.DelayCompression;
import org.apache.sshd.common.kex.extension.parser.Elevation;
import org.apache.sshd.common.kex.extension.parser.NoFlowControl;
import org.apache.sshd.common.kex.extension.parser.ServerSignatureAlgorithms;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Default KEX extension handler
 */
public class DefaultKexExtensionHandler extends AbstractLoggingBean implements KexExtensionHandler {

    private Map<String, Object> local;
    private Map<String, Object> remote;

    public DefaultKexExtensionHandler() {
    }

    public DefaultKexExtensionHandler(Map<String, Object> extensions) {
        this.local = extensions;
    }

    public Map<String, Object> getLocal() {
        return local;
    }

    public Map<String, Object> getRemote() {
        return remote;
    }

    public void addExtension(String name, Object value) {
        if (local == null) {
            local = new HashMap<>();
        }
        local.put(name, value);
    }

    public void sendKexExtensions(Session session, KexPhase phase) throws IOException {
        Map<KexProposalOption, String> options = session.isServerSession()
                ? session.getClientKexProposals()
                : session.getServerKexProposals();
        String signal = session.isServerSession()
                ? KexExtensions.CLIENT_KEX_EXTENSION
                : KexExtensions.SERVER_KEX_EXTENSION;
        String algos = options != null ? options.get(KexProposalOption.ALGORITHMS) : null;
        boolean hasKexExtensions = algos != null && Arrays.asList(algos.split(",")).contains(signal);
        if (hasKexExtensions && local != null && !local.isEmpty()) {
            Buffer buffer = session.createBuffer(KexExtensions.SSH_MSG_EXT_INFO);
            KexExtensions.putExtensions(local.entrySet(), buffer);
            session.writePacket(buffer);
        }
    }

    public boolean handleKexExtensionsMessage(Session session, Buffer buffer) throws IOException {
        List<Entry<String, ?>> extensions = KexExtensions.parseExtensions(buffer);
        remote = new HashMap<>();
        for (Entry<String, ?> extension : extensions) {
            remote.put(extension.getKey(), extension.getValue());
            switch (extension.getKey()) {
                case NoFlowControl.NAME:
                    if (NoFlowControl.PREFERRED.equals(extension.getValue())
                            || NoFlowControl.PREFERRED.equals(this.local.get(NoFlowControl.NAME))) {
                        session.activateNoFlowControl();
                    }
                    break;
                case ServerSignatureAlgorithms.NAME:
                    if (!session.isServerSession()) {
                        Collection<String> sigAlgos = (Collection<String>) extension.getValue();
                        updateAvailableSignatureFactories(session, sigAlgos);
                    }
                    break;
                case Elevation.NAME:
                    if (!session.isServerSession()) {
                        log.warn("The SSH server is not supposed to send an 'elevation' KEX extension");
                    }
                    break;
                case DelayCompression.NAME:
                default:
                    log.debug("Received unsupported KEX extension: {} / {}", extension.getKey(), extension.getValue());
                    break;
            }
        }
        return true;
    }

    /**
     * Update the client session with additional available factories sent by the server.
     */
    public void updateAvailableSignatureFactories(Session session, Collection<String> extraAlgos) {
        List<NamedFactory<Signature>> available = session.getSignatureFactories();
        List<NamedFactory<Signature>> updated = new ArrayList<>(available);
        for (String algo : extraAlgos) {
            SignatureFactory factory = BuiltinSignatures.resolveFactory(algo);
            if (factory == null) {
                log.debug("updateAvailableSignatureFactories({}) skip {} - no factory found", session, algo);
                continue;
            }
            if (!factory.isSupported()) {
                log.debug("updateAvailableSignatureFactories({}) skip {} - not supported", session, algo);
                continue;
            }
            if (available.stream().anyMatch(s -> Objects.equals(factory.getName(), s.getName()))) {
                log.debug("updateAvailableSignatureFactories({}) skip {} - already available", session, factory.getName());
                continue;
            }
            int index = SignatureFactory.resolvePreferredSignaturePosition(updated, factory);
            log.debug("updateAvailableSignatureFactories({}) add {} at position={}", session, factory, index);
            if ((index < 0) || (index >= updated.size())) {
                updated.add(factory);
            } else {
                updated.add(index, factory);
            }
        }
        if (!updated.equals(available)) {
            log.debug("updateAvailableSignatureFactories({}) available={}, updated={}",
                    session, available, updated);
            session.setSignatureFactories(updated);
        }
    }

}
