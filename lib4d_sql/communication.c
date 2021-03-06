#include "fourd.h"
#include "fourd_int.h"
#ifdef WIN32
#define EINPROGRESS WSAEWOULDBLOCK
#else
#include <fcntl.h>
#endif

#define USE_SSL true

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>


/*Init SSL*/
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
    SSL_load_error_strings();			/* Bring in and register error messages */
    method = SSLv2_client_method();		/* Create new client-method instance */
    ctx = SSL_CTX_new(method);			/* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
#endif

long frecv(SOCKET s,unsigned char *buf,int len,int flags)
{
	int rec=0;
	long iResult=0;
	do{
		iResult=recv(s,buf+rec,len-rec, 0);
		if(iResult<0){
			return iResult;
		}else {
			rec+=iResult;
		}
	}while(rec<len);
	return rec;
}

int socket_connect(FOURD *cnx,const char *host,unsigned int port)
{
	struct addrinfo *result = NULL,
			*ptr = NULL,
			hints;
	int iResult=0;
	char sport[50];
	sprintf_s(sport,50,"%d",port);

	//initialize Hints
	ZeroMemory( &hints, sizeof(hints) );
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(host, sport, &hints, &result);
	if ( iResult != 0 ) {

		if (VERBOSE == 1)
			Printf("getaddrinfo failed: %d : %s\n", iResult,gai_strerror(iResult));

		cnx->error_code=-iResult;
		strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,gai_strerror(iResult),ERROR_STRING_LENGTH);
		return 1;
	}

	// Attempt to connect to the first address returned by
	// the call to getaddrinfo
	ptr=result;

	// Create a SOCKET for connecting to server
	cnx->socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (cnx->socket == INVALID_SOCKET) {

		if (VERBOSE == 1)
			Printf("Error at socket(): %ld\n", WSAGetLastError());

		cnx->error_code=-WSAGetLastError();
		strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,"Unable to create socket",ERROR_STRING_LENGTH);
		freeaddrinfo(result);
		return 1;
	}

	// Connect to server.
	iResult = connect( cnx->socket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if (iResult == SOCKET_ERROR) {

		if (VERBOSE == 1)
			Printf("Error at socket(): %ld\n", WSAGetLastError());

		cnx->error_code=-WSAGetLastError();
		strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,"Unable to connect to server",ERROR_STRING_LENGTH);
		freeaddrinfo(result);
		closesocket(cnx->socket);
		cnx->socket = INVALID_SOCKET;
		return 1;
	}

	// Should really try the next address returned by getaddrinfo
	// if the connect call failed
	// But for this simple example we just free the resources
	// returned by getaddrinfo and print an error message

	freeaddrinfo(result);

	if (cnx->socket == INVALID_SOCKET) {

		if (VERBOSE == 1)
			Printf("Unable to connect to server!\n");

		cnx->error_code=-1;
		strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,"Unable to connect to server",ERROR_STRING_LENGTH);
		return 1;
	}

	//SSL set up
#ifdef USE_SSL
	cnx->ctx = InitCTX();
	cnx->ssl = SSL_new(cnx->ctx);
	SSL_set_fd(cnx->ssl, cnx->socket);
	if ( SSL_connect(cnx->ssl) == -1){			/* perform the connection */
    	    Printf("Unable to create SSL connection\n");
	    return 1;
	}
#endif

	return 0;
}

void socket_disconnect(FOURD *cnx)
{
#ifdef WIN32
	iResult = shutdown(cnx->socket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		if (VERBOSE == 1)
			Printf("Socket disconnect failed: %d\n", WSAGetLastError());

		closesocket(cnx->socket);
		cnx->connected=0;
		return ;
	}
#endif
	
	closesocket(cnx->socket);
	cnx->connected=0;
#ifdef USE_SSL
	SSL_CTX_free(cnx->ctx);
#endif
}

int socket_send(FOURD *cnx,const char*msg)
{
	long iResult;
	if (VERBOSE == 1)
		Printf("Send:\n%s",msg);
#ifdef USE_SSl
	iResult = SSL_write(cnx->ssl, msg, (int)strlen(msg));
#else
	iResult = send( cnx->socket, msg, (int)strlen(msg), 0 );
#endif
	if (iResult == SOCKET_ERROR) {
		if (VERBOSE == 1)
			Printf("Send failed: %d\n", WSAGetLastError());

		socket_disconnect(cnx);
		return 1;
	}
	return 0;
}

int socket_send_data(FOURD *cnx,const char*msg,int len)
{
	long iResult;

	if (VERBOSE == 1)
	{
		Printf("Send:%d bytes\n",len);
		PrintData(msg,len);
		Printf("\n");
	}

	// Send an initial buffer
#ifdef USE_SSL
	iResult = SSL_write(cnx->ssl, msg, len);
#else
	iResult = send( cnx->socket, msg, len, 0 );
#endif
	if (iResult == SOCKET_ERROR) {

		if (VERBOSE == 1)
			Printf("Send failed: %d\n", WSAGetLastError());

		socket_disconnect(cnx);
		return 1;
	}
	return 0;
}

int socket_receiv_header(FOURD *cnx,FOURD_RESULT *state)
{
	long iResult=0;
	int offset=0;
	int len=0;
	int crlf=0;
	int grow_size=HEADER_GROW_SIZE;
	int new_size=grow_size;

	//allocate some space to start with
	state->header=calloc(sizeof(char),new_size);

	//read the HEADER only
	do
	{
		offset+=iResult;
		iResult = recv(cnx->socket,state->header+offset,1, 0);
		len+=iResult;
		if(len>new_size-5){
			//header storage nearly full. Allocate more.
			new_size=new_size+sizeof(char)*grow_size;
			state->header=realloc(state->header,new_size);
		}
		if(len>3)
		{
			if(state->header[offset-3]=='\r'
			   &&state->header[offset-2]=='\n'
			   &&state->header[offset-1]=='\r'
			   &&state->header[offset  ]=='\n')
				crlf=1;
		}

	}while(iResult>0 && !crlf);

	if(!crlf)
	{
		if (VERBOSE == 1)
			Printf("Error: Header-end not found\n");
		return 1;
	}

	state->header[len]=0;
	state->header_size=len;

	if (VERBOSE == 1)
		Printf("Receive:\n%s",state->header);
	//there we must add reading data
	//before analyse header 
	//see COLUMN-TYPES section
	return 0;
}

int socket_receiv_data(FOURD *cnx,FOURD_RESULT *state)
{
	long iResult=0;
	int len=0;
	//int end_row=0;
	unsigned int nbCol=state->row_type.nbColumn;
	unsigned int nbRow=state->row_count_sent;
	unsigned int r,c;
	FOURD_TYPE *colType=NULL;
	FOURD_ELEMENT *pElmt=NULL;
	unsigned char status_code=0;
	//int elmt_size=0;
	int elmts_offset=0;

	if (VERBOSE == 1)
		Printf("---Debuging the socket_receiv_data\n");

	colType=calloc(nbCol,sizeof(FOURD_TYPE));

	//bufferize Column type
	for(c=0;c<state->row_type.nbColumn;c++)
		colType[c]=state->row_type.Column[c].type;

	if (VERBOSE == 1)
		Printf("nbCol*nbRow:%d\n",nbCol*nbRow);

	/* allocate nbElmt in state->elmt */
	state->elmt=calloc(nbCol*nbRow,sizeof(FOURD_ELEMENT));

	if (VERBOSE == 1){
		Printf("Debut de socket_receiv_data\n");
		Printf("state->row_count:%d\t\tstate->row_count_sent:%d\n",state->row_count,state->row_count_sent);
		Printf("NbRow to read: %d\n",nbRow);
	}

	/* read all rows */
	for(r=0;r<nbRow;r++)
	{
		/* read status_code and row_id */
		if(state->updateability)  /* rowId is send only if row updateablisity */
		{
			int row_id=0;
			status_code=0;
			iResult = frecv(cnx->socket,&status_code,sizeof(status_code), 0);

			if (VERBOSE == 1)
				Printf("status_code for row:0x%X\n",status_code);

			len+=iResult;

			switch(status_code)
			{
				case '0':
					break;
				case '1':
					/* pElmt->elmt=calloc(vk_sizeof(colType[0]),1); */
					iResult = frecv(cnx->socket,(unsigned char*)&row_id,sizeof(row_id), 0);

					if (VERBOSE == 1)
						Printf("row_id:%d\n",row_id);

					len+=iResult;
					break;
				case '2':
					if (VERBOSE == 1)
						Printferr("Error during reading data\n");

					frecv(cnx->socket,(unsigned char*)&(state->error_code),sizeof(state->error_code), 0);
					free(colType); //before returning, free coll type
					return 1;	/* return on error */
				default:
					if (VERBOSE == 1)
						Printferr("Status code 0x%X not supported in data at row %d column %d\n",status_code,(elmts_offset-c+1)/nbCol+1,c+1);

					free(colType);
					state->error_code=-1;
					sprintf_s(state->error_string,ERROR_STRING_LENGTH,"Status code not supported",ERROR_STRING_LENGTH);
					return 1;
			}
		}
		else {
			if (VERBOSE == 1)
				Printf("Not read rowid\n");
		}

		/* read all columns */
		for(c=0;c<nbCol;c++,elmts_offset++)
		{
			pElmt=&(state->elmt[elmts_offset]);
			pElmt->type=colType[c];

			//read column status code
			status_code=0;
			iResult = frecv(cnx->socket,&status_code,1, 0);

			if (VERBOSE == 1)
				Printf("Status: %2X\n",status_code);

			len+=iResult;
			switch(status_code)
			{
				case '2'://error
					if (VERBOSE == 1)
						Printferr("Error during reading data\n");

					frecv(cnx->socket,(unsigned char*)&(state->error_code),sizeof(state->error_code), 0);
					free(colType);
					return 1;
				case '0'://null value
					if (VERBOSE == 1)
						Printf("Read null value\n");

					pElmt->null=1;
					break;
				case '1'://value
					pElmt->null=0;
					switch(colType[c])
					{
						case VK_BOOLEAN:
						case VK_BYTE:
						case VK_WORD:
						case VK_LONG:
						case VK_LONG8:
						case VK_REAL:
						case VK_DURATION:
							pElmt->pValue=calloc(1,vk_sizeof(colType[c]));
							iResult = frecv(cnx->socket,(pElmt->pValue),vk_sizeof(colType[c]), 0);
							len+=iResult;

							if (VERBOSE == 1)
								Printf("Long: %d\n",*((int*)pElmt->pValue));

							break;
						case VK_TIMESTAMP:
						{
							FOURD_TIMESTAMP *tmp;
							tmp=calloc(1,sizeof(FOURD_TIMESTAMP));
							pElmt->pValue=tmp;
							iResult = frecv(cnx->socket,(unsigned char*)&(tmp->year),2, 0);

							if (VERBOSE == 1)
								Printf("year: %04X",tmp->year);

							len+=iResult;
							iResult = frecv(cnx->socket,(unsigned char*)&(tmp->mounth),1, 0);

							if (VERBOSE == 1)
								Printf("    mounth: %02X",tmp->mounth);

							len+=iResult;
							iResult = frecv(cnx->socket,(unsigned char*)&(tmp->day),1, 0);

							if (VERBOSE == 1)
								Printf("    day: %02X",tmp->day);

							len+=iResult;
							iResult = frecv(cnx->socket,(unsigned char*)&(tmp->milli),4, 0);

							if (VERBOSE == 1)
								Printf("    milli: %08X\n",tmp->milli);

							len+=iResult;
						}
							break;
						case VK_FLOAT:
						{
							//int exp;char sign;int data_length;void* data;
							FOURD_FLOAT *tmp;
							tmp=calloc(1,sizeof(FOURD_FLOAT));
							pElmt->pValue=tmp;

							iResult = frecv(cnx->socket,(unsigned char*)&(tmp->exp),4, 0);
							len+=iResult;

							if (VERBOSE == 1)
								Printf("Exp: %X",tmp->exp);

							iResult = frecv(cnx->socket,(unsigned char*)&(tmp->sign),1, 0);
							len+=iResult;

							if (VERBOSE == 1)
								Printf(" sign: %X",tmp->exp);

							iResult = frecv(cnx->socket,(unsigned char*)&(tmp->data_length),4, 0);
							len+=iResult;

							if (VERBOSE == 1)
								Printf(" length: %X",tmp->exp);

							tmp->data=calloc(tmp->data_length,1);
							iResult = frecv(cnx->socket,(tmp->data),tmp->data_length, 0);

							if (VERBOSE == 1)
								Printf(" data: %X",tmp->data);

							len+=iResult;

						}
							break;
						case VK_STRING:
						{
							int data_length=0;
							FOURD_STRING *str;
							//read negative value of length of string
							str=calloc(1,sizeof(FOURD_STRING));
							pElmt->pValue=str;
							iResult = frecv(cnx->socket,(unsigned char*)&data_length,4, 0);
							len+=iResult;

							if (VERBOSE == 1)
								Printf("String length: %08X\n",data_length);

							data_length=-data_length;
							str->length=data_length;
							str->data=calloc(data_length*2+2,1);
							if(data_length==0){	//correct read for empty string
								str->data[0]=0;
								str->data[1]=0;
							}
							else {
								iResult = frecv(cnx->socket,(str->data),(data_length*2), 0);
								str->data[data_length*2]=0;
								str->data[data_length*2+1]=0;
								len+=iResult;
							}

						}
							break;
						case VK_IMAGE:
						{
							int data_length=0;
							FOURD_IMAGE *blob;
							blob=calloc(1,sizeof(FOURD_IMAGE));
							pElmt->pValue=blob;
							iResult = frecv(cnx->socket,(unsigned char*)&data_length,4, 0);

							if (VERBOSE == 1)
								Printf("Image length: %08X\n",data_length);

							len+=iResult;
							if(data_length==0){
								blob->length=0;
								blob->data=NULL;
								pElmt->null=1;
							}else{
								blob->length=data_length;
								blob->data=calloc(data_length,1);
								iResult = frecv(cnx->socket,blob->data,data_length, 0);
								len+=iResult;
							}

							if (VERBOSE == 1)
								Printf("Image: %d Bytes\n",data_length);

						}
							break;
						case VK_BLOB:
						{
							int data_length=0;
							FOURD_BLOB *blob;
							blob=calloc(1,sizeof(FOURD_BLOB));
							pElmt->pValue=blob;
							iResult = frecv(cnx->socket,(unsigned char*)&data_length,4, 0);

							if (VERBOSE == 1)
								Printf("Blob length: %08X\n",data_length);

							len+=iResult;
							if(data_length==0){
								blob->length=0;
								blob->data=NULL;
								pElmt->null=1;
							}else{
								blob->length=data_length;
								blob->data=calloc(data_length,1);
								iResult = frecv(cnx->socket,blob->data,data_length, 0);
								len+=iResult;
							}

							if (VERBOSE == 1)
								Printf("Blob: %d Bytes\n",data_length);

						}
							break;
						default:
							if (VERBOSE == 1)
								Printferr("Type not supported (%s) at row %d column %d\n",stringFromType(colType[c]),(elmts_offset-c+1)/nbCol+1,c+1);

							break;
					}
					break;
				default:
					if (VERBOSE == 1)
						Printferr("Status code 0x%X not supported in data at row %d column %d\n",status_code,(elmts_offset-c+1)/nbCol+1,c+1);

					break;
			}
		}
	}

	if (VERBOSE == 1)
		Printf("---End of socket_receiv_data\n");

	free(colType);
	return 0;
}

int socket_receiv_update_count(FOURD *cnx,FOURD_RESULT *state)
{
	FOURD_LONG8 data=0;
	frecv(cnx->socket,(unsigned char*)&data,8, 0);

	if (VERBOSE == 1)
		Printf("Ox%X\n",data);

	cnx->updated_row=data;

	if (VERBOSE == 1)
		Printf("\n");

	return 0;
}

int set_sock_blocking(int socketd, int block)
{
	int ret = 0;
	int flags;
	int myflag = 0;

#ifdef WIN32
	/* with ioctlsocket, a non-zero sets nonblocking, a zero sets blocking */
	flags = !block;
	if (ioctlsocket(socketd, FIONBIO, &flags) == SOCKET_ERROR) {
		ret = 1;
	}
#else
	flags = fcntl(socketd, F_GETFL);
#ifdef O_NONBLOCK
	myflag = O_NONBLOCK; /* POSIX version */
#elif defined(O_NDELAY)
	myflag = O_NDELAY;   /* old non-POSIX version */
#endif
	if (!block) {
		flags |= myflag;
	} else {
		flags &= ~myflag;
	}
	fcntl(socketd, F_SETFL, flags);
#endif
	return ret;
}

int socket_connect_timeout(FOURD *cnx,const char *host,unsigned int port,int timeout)
{
	struct addrinfo *result = NULL,
			*ptr = NULL,
			hints;
	int iResult=0,valopt=0;
	struct timeval tv;
	fd_set myset;
	socklen_t lon;

	char sport[50];
	sprintf_s(sport,50,"%d",port);

	/* initialize Hints */
	ZeroMemory( &hints, sizeof(hints) );
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	/* Resolve the server address and port */
	iResult = getaddrinfo(host, sport, &hints, &result);
	if ( iResult != 0 ) {
		if (VERBOSE == 1)
			Printf("getaddrinfo failed: %d : %s\n", iResult,gai_strerror(iResult));

		cnx->error_code=-iResult;
		strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,gai_strerror(iResult),ERROR_STRING_LENGTH);
		return 1;
	}

	/*Attempt to connect to the first address returned by
	 the call to getaddrinfo */
	ptr=result;

	/* Create a SOCKET for connecting to server */
	cnx->socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
	if (cnx->socket == INVALID_SOCKET) {
		if (VERBOSE == 1)
			Printf("Error at socket(): %ld\n", WSAGetLastError());

		cnx->error_code=-WSAGetLastError();
		strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,"Unable to create socket",ERROR_STRING_LENGTH);
		freeaddrinfo(result);
		return 1;
	}
	int flag=1;

	// if we get an error here, we can safely ignore it. The connection may be slower, but it should
	// still work.
	setsockopt(cnx->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));


	/*set Non blocking socket */
	set_sock_blocking(cnx->socket,0);
	/* Connect to server. */
	iResult = connect( cnx->socket, ptr->ai_addr, (int)ptr->ai_addrlen);
	if(iResult<0){
		if (WSAGetLastError() == EINPROGRESS) {
			tv.tv_sec = timeout;
			tv.tv_usec = 0;
			FD_ZERO(&myset);
			FD_SET(cnx->socket, &myset);
			if (select(cnx->socket+1, NULL, &myset, NULL, &tv) > 0) {
				lon = sizeof(int);
				getsockopt(cnx->socket, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
				if (valopt) {
					if (VERBOSE == 1)
						Printf("Error in connection() %d - %s\n", valopt, strerror(valopt));

					cnx->error_code=valopt;
					strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,strerror(valopt),ERROR_STRING_LENGTH);
					freeaddrinfo(result);
					closesocket(cnx->socket);
					cnx->socket = INVALID_SOCKET;
					return 1;
				}
				/*connection ok*/
			}
			else {
				/*fprintf(stderr, "Timeout or error() %d - %s\n", valopt, strerror(valopt)); */
				cnx->error_code=3011;
				strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,"Connect timed out",ERROR_STRING_LENGTH);
				freeaddrinfo(result);
				closesocket(cnx->socket);
				cnx->socket = INVALID_SOCKET;
				return 1;
			}
		}
		else {
			cnx->error_code=-WSAGetLastError();
			strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,"Error connecting",ERROR_STRING_LENGTH);
			freeaddrinfo(result);
			closesocket(cnx->socket);
			cnx->socket = INVALID_SOCKET;
			return 1;
		}
	}

	/* Printf("Connexion ok\n"); */


	/*set blocking socket */
	set_sock_blocking(cnx->socket,1);


	/* Should really try the next address returned by getaddrinfo
	   if the connect call failed
	   But for this simple example we just free the resources
	   returned by getaddrinfo and print an error message */

	freeaddrinfo(result);

	if (cnx->socket == INVALID_SOCKET) {
		if (VERBOSE == 1)
			Printf("Unable to connect to server!\n");

		cnx->error_code=-1;
		strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,"Unable to connect to server",ERROR_STRING_LENGTH);
		return 1;
	}


	return 0;
}
