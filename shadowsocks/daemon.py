#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2014-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import logging
import signal
import time
from shadowsocks import common, shell

# this module is ported from ShadowVPN daemon.c


def daemon_exec(config):
    if 'daemon' in config:
        if os.name != 'posix':
            raise Exception('daemon mode is only supported on Unix')
        command = config['daemon']
        if not command:
            command = 'start'
        pid_file = config['pid-file']
        log_file = config['log-file']
        if command == 'start':
            daemon_start(pid_file, log_file)
        elif command == 'stop':
            daemon_stop(pid_file)
            # always exit after daemon_stop
            sys.exit(0)
        elif command == 'restart':
            daemon_stop(pid_file)
            daemon_start(pid_file, log_file)
        else:
            raise Exception('unsupported daemon command %s' % command)


def write_pid_file(pid_file, pid):
    import fcntl
    import stat

    try:
        fd = os.open(pid_file, os.O_RDWR | os.O_CREAT,
                     stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        shell.print_exception(e)
        return -1
    # fcntl函数出错时返回-1
    # F_GETFD表示获取文件描述符标志,Unix只定义了一个文件描述符标志,
    # 就是FD_CLOEXEC(执行时关闭)
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    assert flags != -1
    flags |= fcntl.FD_CLOEXEC
    r = fcntl.fcntl(fd, fcntl.F_SETFD, flags)
    assert r != -1
    # There is no platform independent way to implement fcntl(fd, F_SETLK, &fl)
    # via fcntl.fcntl. So use lockf instead
    try:
        # lockf实现了fcntl函数的记录锁动作,具体参照apue14.3和python fcntl模块
        # 此处的lockf以不阻塞的方式获取一个排他的写锁
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
    except IOError:
        # lockf抛出IOError表示排他记录锁已被其他进程占有
        r = os.read(fd, 32)
        if r:
            logging.error('already started at pid %s' % common.to_str(r))
        else:
            logging.error('already started')
        os.close(fd)
        return -1
    os.ftruncate(fd, 0)
    os.write(fd, common.to_bytes(str(pid)))
    return 0


def freopen(f, mode, stream):
    oldf = open(f, mode)
    oldfd = oldf.fileno()
    newfd = stream.fileno()
    os.close(newfd)
    os.dup2(oldfd, newfd)


def daemon_start(pid_file, log_file):

    # 信号处理函数的第二个参数为收到信号时的current stack frame
    # _是一个临时变量名称,表示后续不再关注和使用该变量
    def handle_exit(signum, _):
        # stop ssserver时会发送SIGTERM
        if signum == signal.SIGTERM:
            sys.exit(0)
        # 异常退出是指收到SIGINT信号,比如ctrl+C
        sys.exit(1)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # fork only once because we are sure parent will exit
    pid = os.fork()
    assert pid != -1

    if pid > 0:
        # parent waits for its child
        time.sleep(5)
        sys.exit(0)

    # child signals its parent to exit
    ppid = os.getppid()
    pid = os.getpid()
    if write_pid_file(pid_file, pid) != 0:
        os.kill(ppid, signal.SIGINT)
        sys.exit(1)

    # 结合上下文,执行的是创建守护进程的标准步骤,参照apue 13.3节,顺序与书中不太一致
    os.setsid()
    # 一般情况,终端退出是会给其创建的进程发送SIGHUP
    # 由于setsid函数会让进程脱离控制终端,该signal函数是否有必要?
    signal.signal(signal.SIG_IGN, signal.SIGHUP)

    print('started')
    os.kill(ppid, signal.SIGTERM)

    sys.stdin.close()
    # 将log文件分别在stdout和stderr的描述符上打开,用到了dup2函数.
    try:
        freopen(log_file, 'a', sys.stdout)
        freopen(log_file, 'a', sys.stderr)
    except IOError as e:
        shell.print_exception(e)
        sys.exit(1)


def daemon_stop(pid_file):
    import errno
    try:
        with open(pid_file) as f:
            buf = f.read()
            pid = common.to_str(buf)
            if not buf:
                logging.error('not running')
    except IOError as e:
        shell.print_exception(e)
        if e.errno == errno.ENOENT:
            # always exit 0 if we are sure daemon is not running
            logging.error('not running')
            return
        sys.exit(1)
    pid = int(pid)
    if pid > 0:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            if e.errno == errno.ESRCH:
                logging.error('not running')
                # always exit 0 if we are sure daemon is not running
                return
            shell.print_exception(e)
            sys.exit(1)
    else:
        logging.error('pid is not positive: %d', pid)

    # sleep for maximum 10s
    for i in range(0, 200):
        try:
            # query for the pid
            os.kill(pid, 0)
        except OSError as e:
            if e.errno == errno.ESRCH:
                break
        time.sleep(0.05)
    else:
        logging.error('timed out when stopping pid %d', pid)
        sys.exit(1)
    print('stopped')
    os.unlink(pid_file)


def set_user(username):
    if username is None:
        return

    import pwd
    import grp

    try:
        pwrec = pwd.getpwnam(username)
    except KeyError:
        logging.error('user not found: %s' % username)
        raise
    user = pwrec[0]
    uid = pwrec[2]
    gid = pwrec[3]

    cur_uid = os.getuid()
    if uid == cur_uid:
        return
    if cur_uid != 0:
        logging.error('can not set user as nonroot user')
        # will raise later

    # inspired by supervisor
    if hasattr(os, 'setgroups'):
        groups = [grprec[2] for grprec in grp.getgrall() if user in grprec[3]]
        groups.insert(0, gid)
        os.setgroups(groups)
    os.setgid(gid)
    os.setuid(uid)
