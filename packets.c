// Chad Cahill
// EECE 555
// Fall 2013

// some of this code was provided by Dr. Kredo

#include <pcap/pcap.h>
#include <arpa/inet.h>

int openFileOrDevice(int use_file, pcap_t **pcap_handle, char *trace_file, char **dev_name, char pcap_buff[PCAP_ERRBUF_SIZE]);

void printMAC(const u_char *packet_data);

int checkType(const u_char *packet_data);

int printIPv4info(const u_char *packet_data);

int printARPinfo(const u_char *packet_data);

int printIPv6info(const u_char *packet_data);

int printVLANinfo(const u_char *packet_data);

int main(int argc, char *argv[]) {

  char pcap_buff[PCAP_ERRBUF_SIZE];       /* Error buffer used by pcap functions */
  pcap_t *pcap_handle = NULL;             /* Handle for PCAP library */
  struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
  const u_char *packet_data = NULL;       /* Packet data from PCAP */
  int ret = 0;                            /* Return value from library calls */
  char *trace_file = NULL;                /* Trace file to process */
  char *dev_name = NULL;                  /* Device name for live capture */
  char use_file = 0;                      /* Flag to use file or live capture */
  uint16_t type;                          // Value of packet type/length field
  int errorCheck = 0;                     // Flag to check function calls for errors

  /* Check command line arguments */
  if( argc > 2 ) {
    fprintf(stderr, "Usage: %s trace_file\n", argv[0]);
    return -1;
  }
  else if( argc > 1 ){
    use_file = 1;
    trace_file = argv[1];
  }
  else {
    use_file = 0;
  }

  errorCheck = openFileOrDevice(use_file, &pcap_handle, trace_file, &dev_name, pcap_buff);
  if (errorCheck == -1)
  {
    printf("error opening file or device\n");
    return -1;
  }

  /* Loop through all the packets in the trace file.
   * ret will equal -2 when the trace file ends.
   * This is an infinite loop for live captures. */
  ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
  while( ret != -2 ) {

    /* An error occurred */
    if( ret == -1 ) {
      pcap_perror(pcap_handle, "Error processing packet:");
      pcap_close(pcap_handle);
      return -1;
    }

    /* Unexpected return values; other values shouldn't happen when reading trace files */
    else if( ret != 1 ) {
      fprintf(stderr, "Unexpected return value (%i) from pcap_next_ex()\n", ret);
      pcap_close(pcap_handle);
      return -1;
    }

    /* Process the packet and print results */
    else {
      printMAC(packet_data);
      type = checkType(packet_data);

      // print the appropriate packet info 
      // based on the packet type
      // eg. IPv4, IPv6, ARP, VLAN, or Other
      switch (type)
      {
        case 0x0800: // IPv4
          errorCheck = printIPv4info(packet_data);
          if (errorCheck == -1)
          {
            printf("error printing IPv4 information\n"); 
            return -1;
          }
          break;
        case 0x86dd: // IPv6
          errorCheck = printIPv6info(packet_data);
          if (errorCheck == -1)
          {
            printf("error printing IPv6 information\n");
            return -1;
          }
          break;
        case 0x0806: // ARP
          errorCheck = printARPinfo(packet_data);
          if (errorCheck == -1)
          {
            printf("error printing ARP information\n");
            return -1;
          }
          break;
        case 0x8100: // VLAN
          errorCheck = printVLANinfo(packet_data);
          if (errorCheck == -1)
          {
            printf("error printing VLAN information\n");
            return -1;
          }
          break;
        default: // Other
          printf("[Other]");
          break;
      }
      printf("\n");
    }

    /* Get the next packet */
    ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
  }

  /* Close the trace file or device */
  pcap_close(pcap_handle);
  return 0;
}

// input arguments
// use_file: input 0 for no file, input 1 for a file used
// trace_file: name of file to be opened
// return value: openFileOrDevice() returns 0 on success, returns -1 on error
// description: openFileOrDevice() will open either a trace file 
//  or a device to capture packets from
int openFileOrDevice(int use_file, pcap_t **pcap_handle, char *trace_file, char **dev_name, char pcap_buff[PCAP_ERRBUF_SIZE])
{
  /* Open the trace file, if appropriate */
  if( use_file ){
    *pcap_handle = pcap_open_offline(trace_file, pcap_buff);
    if( pcap_handle == NULL ){
      fprintf(stderr, "Error opening trace file \"%s\": %s\n", trace_file, pcap_buff);
      return -1;
    }
    printf("Processing file '%s'\n", trace_file);
  }
  /* Lookup and open the default device if trace file not used */
  else{
    *dev_name = pcap_lookupdev(pcap_buff);
    if( dev_name == NULL ){
      fprintf(stderr, "Error finding default capture device: %s\n", pcap_buff);
      return -1;
    }
    *pcap_handle = pcap_open_live(*dev_name, BUFSIZ, 1, 0, pcap_buff);
    if( pcap_handle == NULL ){
      fprintf(stderr, "Error opening capture device %s: %s\n", *dev_name, pcap_buff);
      return -1;
    }
    printf("Capturing on interface '%s'\n", *dev_name);
  } return 0;
}

// input: packet data from PCAP
// description: prints source and destination MAC address
void printMAC(const u_char *packet_data)
{
  // print MAC src address
  printf("%02X:", packet_data[6]);
  printf("%02X:", packet_data[7]);
  printf("%02X:", packet_data[8]);
  printf("%02X:", packet_data[9]);
  printf("%02X:", packet_data[10]);
  printf("%02X", packet_data[11]);
  printf(" -> ");
  // print MAC dst address
  printf("%02X:", packet_data[0]);
  printf("%02X:", packet_data[1]);
  printf("%02X:", packet_data[2]);
  printf("%02X:", packet_data[3]);
  printf("%02X:", packet_data[4]);
  printf("%02X ", packet_data[5]);
  return;
}

// input: packet data from PCAP
// return value: integer value containing the current packet's type/length value
//  example return values: 0x86dd, 0x0800
// description: checkType() looks at Byte 12 and 13 of packet_data (the
//  type/length field of packet header)
int checkType(const u_char *packet_data)
{
  uint16_t type;
  type = (packet_data[12] << 8) | packet_data[13];
  return type;
}

// input: packet data from PCAP
// return value: printIPv4info() returns 0 on success, returns -1 on error
// description: printIPv4info() cleanly prints IPv4 source and destination addresses
int printIPv4info(const u_char *packet_data)
{
  printf("[IPv4] ");

  // print IPv4 source address
  char src[INET_ADDRSTRLEN];
  char dst[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, ((const void *)(packet_data+26)), src, INET_ADDRSTRLEN);
  if (src == NULL)
  {
    printf("error in inet_ntop ipv4 src\n");
    return -1;
  }
  printf("%s", src);
  printf(" -> ");

  // print IPv4 destination address
  inet_ntop(AF_INET, ((const void *)(packet_data+30)), dst, INET_ADDRSTRLEN);
  if (dst == NULL)
  {
    printf("error in inet_ntop ipv4 dst\n");
    return -1;
  }
  printf("%s", dst);
  return 0;
}

// return value: printARPinfo returns 0 on success, returns -1 on error
// description: printARPinfo first checks if request or reply
//  on requests the requester's IP is first printed followed by the requested IP
//  on replys the provided IP is printed followed by the Ethernet address mapping
int printARPinfo(const u_char *packet_data)
{
  printf("[ARP] ");
  
  char src[INET_ADDRSTRLEN];
  char dst[INET_ADDRSTRLEN];
  if (packet_data[21] == 0x01) // request
  {
    // print requester's IP
    inet_ntop(AF_INET, ((const void *)(packet_data+28)), src, INET_ADDRSTRLEN);
    if (src == NULL)
    {
      printf("error in inet_ntop arp request src\n");
      return -1;
    }

    // print requested IP
    inet_ntop(AF_INET, ((const void *)(packet_data+38)), dst, INET_ADDRSTRLEN);
    if (dst == NULL)
    {
      printf("error in inet_ntop arp request dst\n");
      return -1;
    }
    printf("%s requests %s", src, dst);
  }

  if (packet_data[21] == 0x02) // reply
  {
    // print provided IP
    inet_ntop(AF_INET, ((const void *)(packet_data+28)), src, INET_ADDRSTRLEN);
    if (src == NULL)
    {
      printf("error in inet_ntop arp reply src\n");
      return -1;
    }
    printf("%s at ", src);

    // print Ethernet address mapping
    printf("%02X:", packet_data[32]);
    printf("%02X:", packet_data[33]);
    printf("%02X:", packet_data[34]);
    printf("%02X:", packet_data[35]);
    printf("%02X:", packet_data[36]);
    printf("%02X", packet_data[37]);
  }
  return 0;
}

// input: packet data from PCAP
// return value: printIPv6info() returns 0/-1 on success/error
// description: printIPv6info() cleanly prints the source and destination IPv6 address
int printIPv6info(const u_char *packet_data)
{
  printf("[IPv6] ");

  // print IPv6 source address
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, ((const void *)(packet_data+22)), src, INET6_ADDRSTRLEN);
  if (src == NULL)
  {
    printf("error in inet_ntop ipv4 src\n");
    return -1;
  }
  printf("%s", src);
  printf(" -> "); 

  // print IPv6 destination address
  inet_ntop(AF_INET6, ((const void *)(packet_data+38)), dst, INET6_ADDRSTRLEN);
  if (dst == NULL)
  {
    printf("error in inet_ntop ipv4 dst\n");
    return -1;
  }
  printf("%s", dst);
  return 0;
}

// input: packet data from PCAP
// return value: printVLANinfo() returns 0 on success
// description: printVLANinfo() prints the VLAN ID
int printVLANinfo(const u_char *packet_data)
{
  printf("[VLAN] ");
  int vlanID = 0;
  vlanID = packet_data[14] + packet_data[15];
  printf("ID = %d", vlanID);
  return 0;
}
