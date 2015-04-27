/** References : https://gist.github.com/msantos/939154
    http://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd-part-2/
*/
#include <stdio.h>
#include<errno.h>

#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen

#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<net/ethernet.h>  //For ether_header

#include<sys/socket.h>
#include<arpa/inet.h>

//#include <pcap/bpf.h>
#include <linux/filter.h>

//sudo tcpdump -A -dd -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
struct sock_filter tcp_filter [] = {
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 27, 0, 0x000086dd },
{ 0x15, 0, 26, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 24, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 22, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 2, 0, 0x00000050 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 17, 0x00000050 },
{ 0x28, 0, 0, 0x00000010 },
{ 0x2, 0, 0, 0x00000001 },
{ 0x30, 0, 0, 0x0000000e },
{ 0x54, 0, 0, 0x0000000f },
{ 0x64, 0, 0, 0x00000002 },
{ 0x7, 0, 0, 0x00000005 },
{ 0x60, 0, 0, 0x00000001 },
{ 0x1c, 0, 0, 0x00000000 },
{ 0x2, 0, 0, 0x00000005 },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x50, 0, 0, 0x0000001a },
{ 0x54, 0, 0, 0x000000f0 },
{ 0x74, 0, 0, 0x00000002 },
{ 0x7, 0, 0, 0x00000009 },
{ 0x60, 0, 0, 0x00000005 },
{ 0x1d, 1, 0, 0x00000000 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },
};

void print_tcp_packet(unsigned char* packet, int size);
void process_packet(char* packet, int packet_size);
void print_ip_header(unsigned char* packet, int packet_size);
void print_data (unsigned char* data , int Size);


int main(int argc , char* argv[]){
  unsigned char *packet ;
  int saddr_size ;
  int data_size;
  struct sockaddr saddr;         

  const int max_packet_size = 65536; //Its Big!
  printf("begin: http sniff\n");
  
  packet  = (unsigned char *) malloc(max_packet_size); 
  
  int sock_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)) ;
  if(sock_fd < 0)    {    
    perror("Socket Error");
    return 1;
  }
  struct sock_fprog fcode = {0};
  fcode.len = sizeof(tcp_filter) / sizeof(struct sock_filter);
  fcode.filter = &tcp_filter[0];
  
  setsockopt(sock_fd,SOL_SOCKET,SO_ATTACH_FILTER,&fcode,sizeof(fcode));
  
  while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_fd , packet , max_packet_size , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        process_packet(packet,data_size);
    }
  
  free(packet);
  printf("end: http sniff\n");
  return 0;
}

void process_packet(char* packet, int packet_size)
{
  printf("process_packet: packet size %d \n",packet_size);
  print_tcp_packet(packet, packet_size);
}


void print_ip_header(unsigned char* Buffer, int Size)
{
  //    print_ethernet_header(Buffer , Size);
  struct sockaddr_in source,dest;
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(stdout , "\n");
    fprintf(stdout , "IP Header\n");
    fprintf(stdout , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(stdout , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(stdout , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(stdout , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(stdout , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(stdout , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(stdout , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(stdout , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(stdout , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(stdout , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(stdout , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(stdout , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(stdout , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));

}



void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    fprintf(stdout , "\n\n***********************TCP Packet*************************\n");  
         
    print_ip_header(Buffer,Size);
         
    fprintf(stdout , "\n");
    fprintf(stdout , "TCP Header\n");
    fprintf(stdout , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(stdout , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(stdout , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(stdout , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(stdout , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(stdout , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(stdout , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(stdout , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(stdout , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(stdout , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(stdout , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(stdout , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(stdout , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(stdout , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(stdout , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(stdout , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(stdout , "\n");
    fprintf(stdout , "                        DATA Dump                         ");
    fprintf(stdout , "\n");

    /**
    fprintf(stdout , "IP Header\n");
    print_data(Buffer,iphdrlen);
         
    fprintf(stdout , "TCP Header\n");
    print_data(Buffer+iphdrlen,tcph->doff*4);
    */                           
    fprintf(stdout , "Data Payload\n");    
    print_data(Buffer + header_size , Size - header_size );

    fprintf(stdout , "\n###########################################################\n");
}



void print_data (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(stdout , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(stdout , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(stdout , "."); //otherwise print a dot
            }
            fprintf(stdout , "\n");
        } 
         
        if(i%16==0) fprintf(stdout , "   ");
            fprintf(stdout , " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(stdout , "   "); //extra spaces
            }
             
            fprintf(stdout , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(stdout , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(stdout , ".");
                }
            }
             
            fprintf(stdout ,  "\n" );
        }
    }
}


