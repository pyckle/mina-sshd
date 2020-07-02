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
package org.apache.sshd.shell;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.sun.jna.LastErrorException;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import org.apache.sshd.common.channel.BufferedIoOutputStream;
import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.ChannelSessionAware;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.Signal;
import org.apache.sshd.server.channel.ChannelDataReceiver;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.AsyncCommand;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionHolder;
import org.jline.terminal.Attributes;
import org.jline.terminal.Size;
import org.jline.terminal.impl.jna.JnaNativePty;

/**
 * Bridges the I/O streams between the SSH command and the process that executes it
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
// CHECKSTYLE:OFF
public class JnaProcessShell extends AbstractLoggingBean
        implements AsyncCommand, ChannelSessionAware, ChannelDataReceiver, ServerSessionHolder, SessionHolder<ServerSession> {

    private static final CLibraryExt C_LIBRARY = Native.load(Platform.C_LIBRARY_NAME, CLibraryExt.class);

    private final List<String> command;
    private String cmdValue;
    private ServerSession session;
    private ChannelSession channel;
    private IoOutputStream output;
    private JnaNativePty pty;
    private OutputStream in;
    private InputStream out;
    private int pid;
    private int exitcode;
    private boolean hasExited;

    /**
     * @param command The command components which when joined (with space separator) create the full command to be
     *                executed by the shell
     */
    public JnaProcessShell(Collection<String> command) {
        // we copy the original list so as not to change it
        this.command = new ArrayList<>(
                ValidateUtils.checkNotNullAndNotEmpty(command, "No process shell command(s)"));
        this.cmdValue = GenericUtils.join(command, ' ');
    }

    @Override
    public void setChannelSession(ChannelSession channel) {
        this.channel = Objects.requireNonNull(channel, "No server channel");
        ValidateUtils.checkTrue(pid == 0, "Session set after process started");
        channel.setDataReceiver(this);
    }

    @Override
    public int data(ChannelSession channel, byte[] buf, int start, int len) throws IOException {
        in.write(buf, start, len);
        return len;
    }

    @Override
    public void close() throws IOException {
        // TODO
    }

    @Override
    public void setIoInputStream(IoInputStream in) {
        // TODO
    }

    @Override
    public void setIoOutputStream(IoOutputStream out) {
        output = new BufferedIoOutputStream(this, out);
    }

    @Override
    public void setIoErrorStream(IoOutputStream err) {
        // TODO
    }

    @Override
    public void setInputStream(InputStream in) {
        // TODO
    }

    @Override
    public void setOutputStream(OutputStream out) {
        // TODO
    }

    @Override
    public void setErrorStream(OutputStream err) {
        // TODO
    }

    @Override
    public void setExitCallback(ExitCallback callback) {
        // TODO
    }

    @Override
    public ServerSession getSession() {
        return session;
    }

    @Override
    public ServerSession getServerSession() {
        return session;
    }

    @Override
    public void start(ChannelSession channel, Environment env) throws IOException {
        this.channel = channel;

        Map<String, String> varsMap = env.getEnv();
        for (int i = 0; i < command.size(); i++) {
            String cmd = command.get(i);
            if ("$USER".equals(cmd)) {
                cmd = varsMap.get("USER");
                command.set(i, cmd);
            }
        }
        cmdValue = GenericUtils.join(command, ' ');
        String cmd = command.get(0);
        String[] args = command.toArray(new String[0]);
        args[0] = Paths.get(args[0]).getFileName().toString();

        pty = JnaNativePty.open(null, null);
        int pid = C_LIBRARY.fork();
        if (pid < 0) {
            throw new IOException("Unable to fork");
        } else if (pid == 0) {
            C_LIBRARY.login_tty(pty.getSlave());
            C_LIBRARY.execl(cmd, args);
            throw new IllegalStateException();
        }

        setupPty(env);
        in = pty.getMasterOutput();
        out = pty.getMasterInput();

        new Thread(() -> {
            try {
                byte[] buf = new byte[8192];
                while (isAlive()) {
                    int len = out.read(buf);
                    if (len < 0) {
                        break;
                    }
                    output.writePacket(new ByteArrayBuffer(buf, 0, len));
                }
                destroy(channel);
            } catch (IOException e) {
                e.printStackTrace(System.err);
            }
        }).start();
    }

    protected void setupPty(Environment env) throws IOException {
        Attributes attr = pty.getAttr();
        for (Map.Entry<PtyMode, Integer> e : env.getPtyModes().entrySet()) {
            switch (e.getKey()) {
                case VINTR:
                    attr.setControlChar(Attributes.ControlChar.VINTR, e.getValue());
                    break;
                case VQUIT:
                    attr.setControlChar(Attributes.ControlChar.VQUIT, e.getValue());
                    break;
                case VERASE:
                    attr.setControlChar(Attributes.ControlChar.VERASE, e.getValue());
                    break;
                case VKILL:
                    attr.setControlChar(Attributes.ControlChar.VKILL, e.getValue());
                    break;
                case VEOF:
                    attr.setControlChar(Attributes.ControlChar.VEOF, e.getValue());
                    break;
                case VEOL:
                    attr.setControlChar(Attributes.ControlChar.VEOL, e.getValue());
                    break;
                case VEOL2:
                    attr.setControlChar(Attributes.ControlChar.VEOL2, e.getValue());
                    break;
                case VSTART:
                    attr.setControlChar(Attributes.ControlChar.VSTART, e.getValue());
                    break;
                case VSTOP:
                    attr.setControlChar(Attributes.ControlChar.VSTOP, e.getValue());
                    break;
                case VSUSP:
                    attr.setControlChar(Attributes.ControlChar.VSUSP, e.getValue());
                    break;
                case VDSUSP:
                    attr.setControlChar(Attributes.ControlChar.VDSUSP, e.getValue());
                    break;
                case VREPRINT:
                    attr.setControlChar(Attributes.ControlChar.VREPRINT, e.getValue());
                    break;
                case VWERASE:
                    attr.setControlChar(Attributes.ControlChar.VWERASE, e.getValue());
                    break;
                case VLNEXT:
                    attr.setControlChar(Attributes.ControlChar.VLNEXT, e.getValue());
                    break;
                        /*
                        case VFLUSH:
                            attr.setControlChar(ControlChar.VMIN, e.getValue());
                            break;
                        case VSWTCH:
                            attr.setControlChar(ControlChar.VTIME, e.getValue());
                            break;
                        */
                case VSTATUS:
                    attr.setControlChar(Attributes.ControlChar.VSTATUS, e.getValue());
                    break;
                case VDISCARD:
                    attr.setControlChar(Attributes.ControlChar.VDISCARD, e.getValue());
                    break;
                case ECHO:
                    attr.setLocalFlag(Attributes.LocalFlag.ECHO, e.getValue() != 0);
                    break;
                case ICANON:
                    attr.setLocalFlag(Attributes.LocalFlag.ICANON, e.getValue() != 0);
                    break;
                case ISIG:
                    attr.setLocalFlag(Attributes.LocalFlag.ISIG, e.getValue() != 0);
                    break;
                case ICRNL:
                    attr.setInputFlag(Attributes.InputFlag.ICRNL, e.getValue() != 0);
                    break;
                case INLCR:
                    attr.setInputFlag(Attributes.InputFlag.INLCR, e.getValue() != 0);
                    break;
                case IGNCR:
                    attr.setInputFlag(Attributes.InputFlag.IGNCR, e.getValue() != 0);
                    break;
                case OCRNL:
                    attr.setOutputFlag(Attributes.OutputFlag.OCRNL, e.getValue() != 0);
                    break;
                case ONLCR:
                    attr.setOutputFlag(Attributes.OutputFlag.ONLCR, e.getValue() != 0);
                    break;
                case ONLRET:
                    attr.setOutputFlag(Attributes.OutputFlag.ONLRET, e.getValue() != 0);
                    break;
                case OPOST:
                    attr.setOutputFlag(Attributes.OutputFlag.OPOST, e.getValue() != 0);
                    break;
            }
        }
        pty.setAttr(attr);
        env.addSignalListener((ch, signal) -> {
            try {
                pty.setSize(getPtySize(env));
            } catch (IOException e) {
                log.debug("Error changing pty size", e);
            }
        }, Signal.WINCH);
        pty.setSize(getPtySize(env));
    }

    protected Size getPtySize(Environment env) {
        return new Size(Integer.parseInt(env.getEnv().get("COLUMNS")), Integer.parseInt(env.getEnv().get("LINES")));
    }

    public boolean isAlive() {
        return C_LIBRARY.kill(pid, 0) == 0;
    }

    public int exitValue() {
        if (!hasExited) {
            int[] status = new int[1];
            C_LIBRARY.waitpid(pid, status, 0);
            exitcode = status[0];
            hasExited = true;
        }
        return exitcode;
    }

    @Override
    public void destroy(ChannelSession channel) {
        // NOTE !!! DO NOT NULL-IFY THE PROCESS SINCE "exitValue" is called subsequently
        boolean debugEnabled = log.isDebugEnabled();
        if (pid != 0) {
            if (debugEnabled) {
                log.debug("destroy({}) Destroy process for '{}'", channel, cmdValue);
            }
            C_LIBRARY.kill(pid, 9);
            pid = 0;
        }

        // TODO: close master
        IOException e = IoUtils.closeQuietly(in, out, output);
        if (e != null) {
            if (debugEnabled) {
                log.debug("destroy({}) {} while destroy streams of '{}': {}",
                        channel, e.getClass().getSimpleName(), this, e.getMessage());
            }

            if (log.isTraceEnabled()) {
                Throwable[] suppressed = e.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable t : suppressed) {
                        log.trace("destroy({}) Suppressed {} while destroy streams of '{}': {}",
                                channel, t.getClass().getSimpleName(), this, t.getMessage());
                    }
                }
            }
        }
    }

    @Override
    public String toString() {
        return GenericUtils.isEmpty(cmdValue) ? super.toString() : cmdValue;
    }

    // CHECKSTYLE:OFF
    public interface CLibraryExt extends com.sun.jna.Library {

        int fork();

        int login_tty(int fd) throws LastErrorException;

        int execl(String path, String... options) throws LastErrorException;

        int kill(int pid, int sig) throws LastErrorException;

        int waitpid(int pid, int[] status, int options);

    }
}
