# paramiko

## python交互的模块挺多：pexpect、paramiko 、fabric、

前两个包使用过，但独 paramiko  频率高， 简单丰富，重要的是还多坑！有句老实话不知当不当讲，越骚动的郑就越喜欢，因为征服了它就能征服天下

一 、安装

- 省略

	```
	 #
	```

二、 工程测试实例

-  公用

	```
	class SSHConn(object):
	    __ssh = None
	    __transport = None
	    __LOGIN_SUCCESS__ = False
	
	    def __init__(self, host, port, username, password):
	        self.__host = host
	        self.__port = port
	        self.__username = username
	        self.__password = password
	
	    def login(self):
	        """ 登入测试 """
	        error_msg = None
	        try:
	            transport = paramiko.Transport((self.__host, int(self.__port)))
	            transport.start_client()
	            transport.auth_password(self.__username, self.__password)
	            # transport.connect(username=self.__username, password=self.__password)
	            if transport.active is True:
	                self.__LOGIN_SUCCESS__ = True
	                ssh = paramiko.SSHClient()
	                ssh._transport = transport
	                self.__ssh = ssh
	                self.__transport = transport
	        except Exception:
	            error_msg = traceback.format_exc()
	            # error_msg = f'{e}'
	        finally:
	            return self.__LOGIN_SUCCESS__, error_msg
	
	    def send_channel(self, cmd, channel):
	        cmd = str(cmd) + '\r'
	        # 通过命令执行提示符来判断命令是否执行完成
	        # p = re.compile(r']$')
	        result = ''
	        # 发送要执行的命令
	        channel.send(cmd)
	        count = 1
	        # 回显很长的命令可能执行较久，通过循环分批次取回回显
	        # root 用户非root用户回显的内容不一样，循环判断逻辑需要修改
	        if self.__username == 'root':
	            while '~]#' not in result:
	                time.sleep(0.5)
	                count += 1
	                print("count: ", count)
	                ret = channel.recv(65535)
	                ret = ret.decode('utf-8')
	                result += ret
	                # if p.search(ret):
	                if 'Permission denied' in result:
	                    break
	                elif 'password for {0}'.format(self.__username) in result:
	                    break
	            return result
	        # 普通用户
	        while '~]$' not in result:
	            time.sleep(0.5)
	            count += 1
	            print("count: ", count)
	            ret = channel.recv(65535)
	            ret = ret.decode('utf-8')
	            result += ret
	            # if p.search(ret):
	            if 'Permission denied' in result:
	                break
	            elif 'password for {0}'.format(self.__username) in result:
	                break
	        return result
	
	    def check_login(self):
	        """ 检查登入状态 """
	        json_ret, error_msg = self.login()
	        if self.__LOGIN_SUCCESS__ is not False:
	            return json_ret, error_msg
	        return "检查到未登入"
	
	    def close(self):
	        """ 关闭连接/传输 """
	        if self.__LOGIN_SUCCESS__:
	            self.__ssh.close()
	            self.__transport.close()
	        else:
	            return "登入失败"
	```
	
- 调用公用满足业务逻辑
	
	```
	 def run_cmd(self, cmd):
	        """ 执行命令 获取系统cmd列表内相关信息接口 """
	        json_ret = {"code": 200, "msg": "执行成功", "data": []}
	        if type(cmd) is dict:
	            inner_dict = dict()
	            for k, v in cmd.items():
	                # 打开通道
	                channel = self.__transport.open_session()
	                channel.settimeout(100)
	                # 获取终端
	                channel.get_pty()
	                # 激活
	                channel.invoke_shell()
	                str_res = self.send_channel(v, channel)
	                print('====')
	                print('str_res_ooo1: ', str_res)
	                print('------')
	                # 可能会出现回显的用if判断
	                if 'Permission denied' in str_res:
	                    str_res = self.send_channel('sudo {0}'.format(v), channel)
	                    print('retttt: ', str_res)
	
	                    if 'password for {0}'.format(self.__username) in str_res:
	                        str_res = self.send_channel(self.__password, channel)
	                        print("str_res11______password: ", str_res)
	
	                elif 'password for {0}'.format(self.__username) in str_res:
	                    str_res = self.send_channel(self.__password, channel)
	                    print("str_res22______password: ", str_res)
	                # self.close()
	                # print('resp: ', type(resp),  resp)
	                # ret = str(resp, encoding='utf-8', errors='ignore')
	                # 以原始键值对返回数据，暂不做处理
	                print('str_res_00: ', type(str_res), str_res)
	                if str_res and '\n' in str_res:
	                    print(1111)
	                    print('str_res__11: ', len(str_res), type(str_res), str_res)
	                    # json_ret['data'].append({k: str_res})
	                    inner_dict[k] = str_res
	                elif not str_res or str_res == '' or str_res == 'null':
	                    print(2222)
	                    # json_ret['data'].append({k: None})
	                    inner_dict[k] = None
	                    print('json_ret__222')
	                else:
	                    print(3333)
	                    json_ret['msg'] = "未知回显数据及类型"
	                    inner_dict[k] = 'null'
	            json_ret['data'].append(inner_dict)
	            return {"code": 200, "msg": "执行成功", "data": {"data": [inner_dict]}}
	        elif type(cmd) is list:
	            try:
	                for k_v in cmd:
	                    for k, v in k_v.items():
	                        # 打开通道
	                        channel = self.__transport.open_session()
	                        channel.settimeout(100)
	                        # 获取终端
	                        channel.get_pty()
	                        # 激活
	                        channel.invoke_shell()
	                        str_res = self.send_channel(v, channel)
	                        print('====')
	                        print('str_res_ooo1: ', str_res)
	                        print('------')
	                        # 可能会出现回显的用if判断
	                        if 'Permission denied' in str_res:
	                            str_res = self.send_channel('sudo {0}'.format(v), channel)
	                            print('retttt: ', str_res)
	
	                            if 'password for {0}'.format(self.__username) in str_res:
	                                str_res = self.send_channel(self.__password, channel)
	                                print("str_res11______password: ", str_res)
	
	                        elif 'password for {0}'.format(self.__username) in str_res:
	                            str_res = self.send_channel(self.__password, channel)
	                            print("str_res22______password: ", str_res)
	                        # self.close()
	                        # print('resp: ', type(resp),  resp)
	                        # ret = str(resp, encoding='utf-8', errors='ignore')
	                        # 以原始键值对返回数据，暂不做处理
	                        print('str_res_00: ', type(str_res), str_res)
	                        if str_res and '\n' in str_res:
	                            print('str_res__11: ', len(str_res), type(str_res), str_res)
	                            json_ret['data'].append({k: str_res})
	                        elif not str_res or str_res == '' or str_res == 'null':
	                            json_ret['data'].append({k: None})
	                            print('json_ret__222')
	                        else:
	                            json_ret['msg'] = "未知回显数据及类型"
	                            json_ret['data'].append({k: 'null'})
	                # return json_ret
	            except Exception:
	                # json_ret['msg'] = f"错误原因：{e}"
	                json_ret['msg'] = traceback.format_exc()
	                json_ret['code'] = -1
	            finally:
	                return json_ret
	        else:
	            json_ret['msg'] = "仅支持输入 [{'k':'cmd'}] 格式数据"
	        return json_ret
	```
	
- 业务逻辑可参考

	```
		def sys_status(self):
	        """ 获取获取运行状况 """
	        cmd_dict = {"disk_free": "df -k", "mem_free": "free", "ps_aux": "ps -aux", "netstat": "netstat -atunp",
	                    "vmstat": "vmstat"}
	        json_ret = self.run_cmd(cmd_dict)
	        return json_ret
	
	    def sys_info(self):
	        """ 获取系统 cmd_list 列表内相关信息接口 """
	        cmd_list = [{"hostname": 'hostname'}, {'kernel_version': 'uname -r'},
	                    {"release_version": "cat /etc/redhat-release"},
	                    {"ifconfig": "ifconfig"}, {"etc_passwd": "cat /etc/passwd"}, {"etc_group": "cat /etc/group"},
	                    {"etc_login_defs": "cat /etc/login.defs"}, {"etc_pam_system_auth": "cat /etc/pam.d/system-auth"},
	                    {"chkconfig_list": "chkconfig --list"}, {"etc_profile": "cat /etc/profile"},
	                    {"etc_initab": "cat /etc/initab"}, {"etc_sshd_config": "cat /etc/sshd_config"},
	                    {"etc_snmpd_conf": "cat /etc/snmp/snmpd.conf"},
	                    {"sensitive_file_permission": "ls -al /etc/passwd"},
	                    {"sensitive_file_permission": "ls -al /etc/group"},
	                    {"sensitive_file_permission": "ls -al /etc/shadow"},
	                    {"cat_shadow": "cat /etc/shadow"},
	                    {"log_file_permission": "ls -al /var/log/secure"},
	                    {"log_file_permission": "ls -al /var/log/message"},
	                    {"log_file_permission": "ls -al /var/log/cron"},
	                    {"syslog_conf": "cat /etc/syslog.conf"}, {"syslog_conf": "cat /etc/rsyslog.conf"}]
	
	        json_ret = self.run_cmd(cmd_list)
	        return json_ret
	```

- 拓展，切换用户需要使用到 **ssh.invoke_shell()** 打开终端，其他通道方式不行，此下内容来自博友：[戳她](https://blog.csdn.net/weixin_42252770/article/details/99697415?utm_medium=distribute.pc_relevant.none-task-blog-BlogCommendFromBaidu-7.control&depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromBaidu-7.control)

	```
	import paramiko
		import time
		
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
		    ssh.connect(hostname="250.250.250.250", port=80, username="username", password="password")
		    channel = ssh.invoke_shell()
		    time.sleep(0.1)
		    
		    channel.send("su - \n")
		    buff = ''
		    while not buff.endswith('Password: '):
		        resp = channel.recv(9999)
		        buff += resp.decode('utf-8')
		    # print(buff)
		    
		    channel.send("Changeme_123")
		    channel.send('\n')
		    buff = ''
		    while not buff.endswith('# '):  # 当指令执行结束后，Linux窗口会显示#，等待下条指令，所以可以用作识别全部输出结束的标志。
		        resp = channel.recv(9999)
		        buff += resp.decode('utf-8')
		    # print(buff)
		
		    print("------end------")
		   
			# 查看是否切换成功
			channel.send("whoami")
			channel.send("\n")
			buff = ''
			while not buff.endswith('# '):
			    resp = channel.recv(9999)
			    buff += resp.decode('utf-8')
			print(buff)
			
		except paramiko.ssh_exception.AuthenticationException:
		    print('Failed to login. ip username or password not correct.')
		    exit(-1)
	```

	
