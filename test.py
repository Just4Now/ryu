from scapy.all import *
from time import sleep

def case1():
    l = []
    l.append(Ether(dst='00:00:00:00:00:01')/IP(dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:02')/IP(dst='10.0.0.5')/TCP())
    l.append(Ether(dst='00:00:00:00:00:03')/IP(dst='10.0.0.6')/UDP())

    for a in l:
        sendp(a,iface='en4')
        sleep(2)

def case2():
    l = []
    l.append(Ether(dst='00:00:00:00:00:01')/IP(dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:02')/IP(dst='10.0.0.5')/TCP())
    l.append(Ether(dst='00:00:00:00:00:03')/IP(dst='10.0.0.6')/UDP())

    for a in l:
        sendp(a,iface='en4')

def case3():
    l = []
    l.append(Ether(dst='00:00:00:00:00:01')/IP(dst='10.0.0.5')/TCP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(dst='10.0.0.5')/TCP(flags=1))
    l.append(Ether(dst='00:00:00:00:00:02')/IP(dst='10.0.0.6')/TCP())
    l.append(Ether(dst='00:00:00:00:00:02')/IP(dst='10.0.0.6')/TCP(flags=4))
    

    for a in l:
        sendp(a,iface='en4')
        sleep(2)

def case4():
    data='a'*1460
    l=[]
    #l.append(Ether(dst='00:00:00:00:00:01')/IP(dst='10.0.0.4')/ICMP()/data)
    l.append(Ether(dst='00:00:00:00:00:02')/IP(dst='10.0.0.5')/TCP()/data)
    #l.append(Ether(dst='00:00:00:00:00:03')/IP(dst='10.0.0.6')/UDP()/data)
    
    for a in l:
        sendp(a,iface='en4',count=1)
        sleep(random.randint(10,20))

def case5():
    l = []
    l.append(Ether(dst='00:00:00:00:00:01')/IP(dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:02')/IP(dst='10.0.0.5')/TCP())
    l.append(Ether(dst='00:00:00:00:00:03')/IP(dst='10.0.0.6')/UDP())

    for a in l:
        sendp(a,iface='en4')
        #sleep(2)

def case6():
    l = []
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.1', dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.2', dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.3', dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.4', dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.5', dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.6', dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.7', dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.8', dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.9', dst='10.0.0.4')/ICMP())
    l.append(Ether(dst='00:00:00:00:00:01')/IP(src='20.0.0.10', dst='10.0.0.4')/ICMP())

    for a in l:
        sendp(a,iface='en4')
        #sleep(2)

def case78():
    data1 = 'a' * 958
    data2 = 'b' * 1046
    data3 = 'c' * 1158
    l = []
    l.append(Ether(dst='00:00:00:00:00:01')/IP(tos=0xa0,dst='10.0.0.4')/ICMP()/data1)
    l.append(Ether(dst='00:00:00:00:00:02')/IP(tos=0xb0,dst='10.0.0.5')/TCP(sport=1234,dport=21)/data2)
    l.append(Ether(dst='00:00:00:00:00:03')/IP(tos=0xc0,dst='10.0.0.6')/UDP(sport=4321,dport=64)/data3)

    sendp(l[0],iface='en4',count=5)
    sendp(l[1],iface='en4',count=10)
    sendp(l[2],iface='en4',count=20)


def randip():
    s = '%i.%i.%i.%i'%(random.randint(1,254),random.randint(50,99),random.randint(50,99),random.randint(1,254))
    return s

def randport():
    p = random.randint(1025,9999)
    return p

def case9_1():
    for i in range(20):
        data1 = 'a' * random.randint(111,1000)
        data2 = 'b' * random.randint(111,1000)
        data3 = 'c' * random.randint(111,1000)
        l = []
        l.append(Ether(dst='00:00:00:00:00:01')/IP(src=randip(),dst=randip())/ICMP()/data1)
        sp=randport()
        dp=randport()
        l.append(Ether(dst='00:00:00:00:00:02')/IP(src=randip(),dst=randip())/TCP(sport=sp,dport=dp)/data2)
        sp=randport()
        dp=randport()
        l.append(Ether(dst='00:00:00:00:00:03')/IP(src=randip(),dst=randip())/UDP(sport=sp,dport=dp)/data3)
        for a in l:
            sendp(a,iface='en4',count=random.randint(100,500))

def case9_0():
    for i in range(5):
        data1 = 'a' * random.randint(111,1000)
        data2 = 'b' * random.randint(111,1000)
        data3 = 'c' * random.randint(111,1000)
        l = []
        #l.append(Ether(dst='00:00:00:00:00:01')/IP(src=randip(),dst=randip())/ICMP()/data1)
        sp=randport()
        dp=randport()
        l.append(Ether(dst='00:00:00:00:00:02')/IP(src=randip(),dst=randip())/TCP(sport=sp,dport=dp)/data2)
        sp=randport()
        dp=randport()
        l.append(Ether(dst='00:00:00:00:00:03')/IP(src=randip(),dst=randip())/UDP(sport=sp,dport=dp)/data3)
        for a in l:
            sendp(a,inter=1,iface='en4',count=random.randint(10,30))

def linshi():
    for i in range(5):
        data2 = 'b' * random.randint(111,1000)
        l = []
        l.append(Ether(dst='00:00:00:00:00:02')/IP(tos=0xb0,dst='10.0.0.5')/TCP(sport=1234,dport=21)/data2)
        for a in l:
            sendp(a,iface='en4',count=random.randint(10,200))
        sleep(15)

def case_detect():
    while True:
        i = 80 + random.randint(-20,20)
        j = 0
        while j < i:
            data1 = 'a' * random.randint(1, 1000)
            sp = randport()
            dp = randport()
            l.append(Ether(dst='00:00:00:00:00:01')/IP(src=randip(), dst=randip())/TCP(sport=sp, dport=dp, flags=0)/data3)
            for a in l:
                    sendp(a,inter=1,iface='en4',count=random.randint(0,160))
            j = j + 1