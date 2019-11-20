#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif



#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) || \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_RSA_C) ||         \
    !defined(MBEDTLS_CERTS_C) || !defined(MBEDTLS_PEM_PARSE_C) || \
    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_X509_CRT_PARSE_C)
#endif
#if 0
int main( void )
{

    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_CLI_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
           "not defined.\n");

    return( 0 );
}
#else

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"
#include "ca_cert.h"
#include "client.h"
#include "cmsis_os.h"
#include "stm32f7xx_hal_rng.h"
#include <string.h>

static mbedtls_net_context server_fd;
static uint32_t flags;
static uint8_t buf[1024];
static const uint8_t *pers = (uint8_t *)("ssl_client");
static uint8_t vrfy_buf[512];
static void mydebug(void *ctx, int level, const char *file, int line,const char *str);
static int ret;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;

/* use static allocation to keep the heap size as low as possible */
#ifdef MBEDTLS_MEMORY_BUFFER_ALLOC_C
uint8_t memory_buf[MAX_MEM_SIZE];
#endif

typedef struct _wsclient_frame {
	unsigned int fin;
	unsigned int opcode;
	unsigned int mask_offset;
	unsigned int payload_offset;
	unsigned int rawdata_idx;
	unsigned int rawdata_sz;
	unsigned long long payload_len;
	char *rawdata;
	struct _wsclient_frame *next_frame;
	struct _wsclient_frame *prev_frame;
	unsigned char mask[4];
} wsclient_frame;

void close(){
	  mbedtls_ssl_close_notify( &ssl );
	  mbedtls_net_free( &server_fd );
	  mbedtls_x509_crt_free( &cacert );
	  mbedtls_ssl_free( &ssl );
	  mbedtls_ssl_config_free( &conf );
	  mbedtls_ctr_drbg_free( &ctr_drbg );
	  mbedtls_entropy_free( &entropy );
}
int init(){
	  /*
	   * 0. Initialize the RNG and the session data
	   */
	#ifdef MBEDTLS_MEMORY_BUFFER_ALLOC_C
	  mbedtls_memory_buffer_alloc_init(memory_buf, sizeof(memory_buf));
	#endif
	  mbedtls_net_init(NULL);
	  mbedtls_ssl_init(&ssl);
	  mbedtls_ssl_config_init(&conf);
	  mbedtls_x509_crt_init(&cacert);
	  mbedtls_ctr_drbg_init(&ctr_drbg);

}
int seed_rng(){
	  int len;
	  mbedtls_printf( "\n  . Seeding the random number generator..." );
	  mbedtls_entropy_init( &entropy );
	  len = strlen((char *)pers);
	  if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
	                             (const unsigned char *) pers, len ) ) != 0 )
	  {
	    mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
	    return -1;
	  }

	mbedtls_printf( " ok\n" );
	  return 0;
}
int init_cert(){
	 mbedtls_printf( "  . Loading the CA root certificate ..." );

	  ca_crt_rsa[ca_crt_rsa_size - 1] = 0;


	  ret = mbedtls_x509_crt_parse( &cacert,(uint8_t *)ca_crt_rsa, ca_crt_rsa_size);
	  if( ret < 0 )
	  {
	    mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
	    close();
	    return -1;
	  }

	  mbedtls_printf( " ok (%d skipped)\n", ret );
	  return 0;
}
int connect() {
	  mbedtls_printf( "  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT );

	  if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
	                                       SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
	  {
	    mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
	    return -1;
	  }

	  mbedtls_printf( " ok\n" );
}
int tls_init(){

	  mbedtls_printf( "  . Setting up the SSL/TLS structure..." );

	  if( ( ret = mbedtls_ssl_config_defaults( &conf,
	                  MBEDTLS_SSL_IS_CLIENT,
	                  MBEDTLS_SSL_TRANSPORT_STREAM,
	                  MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
	  {
	    mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
	    return -1;
	  }

	  mbedtls_printf( " ok\n" );

	  mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
	  mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
	  mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
	  mbedtls_ssl_conf_dbg(&ssl, mydebug, NULL);
	  mbedtls_debug_set_threshold(4);
	  if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
	  {
	    mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
	    return -1;
	  }

	  if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
	  {
	    mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
	    return -1;
	  }

	  mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
	  return 0;
}
int handshake(){
	  mbedtls_printf( "  . Performing the SSL/TLS handshake..." );

	  while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
	  {
	    if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
	    {
	      mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
	      return -1;
	    }
	  }

	  mbedtls_printf( " ok\n" );
	  return 0;
}
int verify_cert(){
	 mbedtls_printf( "  . Verifying peer X.509 certificate..." );

	  if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
	  {
	    mbedtls_printf( " failed\n" );
	    mbedtls_x509_crt_verify_info( (char *)vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
	    mbedtls_printf( "%s\n", vrfy_buf );
	    return -1;
	  }
	  mbedtls_printf( " ok\n" );
	  return 0;
}
int send(char * message){
	int len;
	mbedtls_printf( "  > Write to server:" );

	sprintf( (char *) buf, message );
	len = strlen((char *) buf);

	while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
	{
		if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
		{
		  mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
		  return -1;
		}
	}

	len = ret;
	mbedtls_printf( " %d bytes written\n\n%s", len, (char *) buf );
	return 0;
}
int ws_handshake(){
	char request_headers[1024];

	uint32_t no = HAL_RNG_GetRandomNumber(&RngHandle);


	snprintf(request_headers, 1024, "GET %s HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: %s:%s\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", "/", SERVER_NAME, SERVER_PORT);
	if(send(request_headers) == -1){
		return -1;
	}


	int n, len, z = 0;
	len = sizeof( buf ) - 1;
	memset( buf, 0, sizeof( buf ) );
	while(NULL == strstr( buf,"\r\n\r\n")) {
			n = mbedtls_ssl_read( &ssl, buf, len );
			mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );

	}

	// WAITING FOR DATA BUT NOT ACTUALLY PARSING STUFF

	return 0;
}
int ws_send(char *strdata){
	unsigned char mask[4];
	unsigned int mask_int;
	unsigned long long payload_len;
	unsigned char finNopcode;
	unsigned int payload_len_small;
	unsigned int payload_offset = 6;
	unsigned int len_size;
	unsigned long long be_payload_len;
	unsigned int sent = 0;
	int i, sockfd;
	unsigned int frame_size;
	char *data;


	finNopcode = 0x81; //FIN and text opcode.
	mask_int = (unsigned int) HAL_RNG_GetRandomNumber(&RngHandle);
	memcpy(mask, &mask_int, 4);
	payload_len = strlen(strdata);
	if(payload_len <= 125) {
		frame_size = 6 + payload_len;
		payload_len_small = payload_len;

	} else if(payload_len > 125 && payload_len <= 0xffff) {
		frame_size = 8 + payload_len;
		payload_len_small = 126;
		payload_offset += 2;
	} else if(payload_len > 0xffff && payload_len <= 0xffffffffffffffffLL) {
		frame_size = 14 + payload_len;
		payload_len_small = 127;
		payload_offset += 8;
	} else {
		return -1; //too large payload
	}
	data = (char *)malloc(frame_size);
	memset(data, 0, frame_size);
	*data = finNopcode;
	*(data+1) = payload_len_small | 0x80; //payload length with mask bit on
	if(payload_len_small == 126) {
		payload_len &= 0xffff;
		len_size = 2;
		for(i = 0; i < len_size; i++) {
			*(data+2+i) = *((char *)&payload_len+(len_size-i-1));
		}
	}
	if(payload_len_small == 127) {
		payload_len &= 0xffffffffffffffffLL;
		len_size = 8;
		for(i = 0; i < len_size; i++) {
			*(data+2+i) = *((char *)&payload_len+(len_size-i-1));
		}
	}
	for(i=0;i<4;i++)
		*(data+(payload_offset-4)+i) = mask[i];

	memcpy(data+payload_offset, strdata, strlen(strdata));
	for(i=0;i<strlen(strdata);i++)
		*(data+payload_offset+i) ^= mask[i % 4] & 0xff;
	sent = 0;
	i = 0;

	while(sent < frame_size && i >= 0) {
		i = mbedtls_ssl_write( &ssl, data+sent, frame_size - sent );
		sent += i;
	}
	return 0;
}
void receive(){
	int len;
	mbedtls_printf( "  Started Receiving Thread\n" );
	do
	{
		len = sizeof( buf ) - 1;
		memset( buf, 0, sizeof( buf ) );
		ret = mbedtls_ssl_read( &ssl, buf, len );

		if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
		{
		  continue;
		}

		if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
		{
		  break;
		}

		if( ret < 0 )
		{
		  mbedtls_printf( "failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
		  break;
		}

		if( ret == 0 )
		{
		  mbedtls_printf( "\n\nEOF\n\n" );
		  break;
		}

		len = ret;
		mbedtls_printf( " %d bytes read:%s\n", len, buf );
	}while( 1 );
}
void SSL_Client()
{

	init();

	if(-1 == seed_rng()){
	    close();
	}

	if(-1 == init_cert()){
	    close();
	}
	if(-1 == connect()){
		close();
	}
	if(-1 == tls_init()){
		close();
	}
	if(-1 == handshake()){
		close();
	}
	verify_cert();
	if(-1 == ws_handshake()){
		close();
	}
	mbedtls_printf( "  > websocket connection established\r\n" );

	osThreadDef(RECEIVE, receive, osPriorityAboveNormal, 0, configMINIMAL_STACK_SIZE * 5);
	osThreadCreate (osThread(RECEIVE), NULL);
	if(-1 == ws_send("small echo test")){
		mbedtls_printf( " couldnt send message\r\n" );
	}







}
/**
     * Debug callback for mbed TLS
     * Just prints on the USB serial port
     */
    static void mydebug(void *ctx, int level, const char *file, int line,
                         const char *str)
    {
        const char *p, *basename;
        (void) ctx;

        /* Extract basename from file */
        for(p = basename = file; *p != '\0'; p++) {
            if(*p == '/' || *p == '\\') {
                basename = p + 1;
            }
        }

        mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
    }
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&
          MBEDTLS_CERTS_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_X509_CRT_PARSE_C */
