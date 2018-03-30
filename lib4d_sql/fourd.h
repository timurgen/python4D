#ifndef __FOURD__
#define __FOURD__ 1

/*
 * Sockets
 */
#ifdef WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <Wspiapi.h>
#else
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netinet/tcp.h>
	#include <arpa/inet.h>
	#include <unistd.h> /* close */
	#include <errno.h>
	#include <netdb.h> /* gethostbyname */
	#define INVALID_SOCKET -1
	#define SOCKET_ERROR -1
	#define closesocket(s) close(s)
	typedef int SOCKET;
	typedef struct sockaddr_in SOCKADDR_IN;
	typedef struct sockaddr SOCKADDR;
	typedef struct in_addr IN_ADDR;
#endif

#define VERBOSE 0
#define SOCKET_TIMEOUT 15
#define MAX_COL_TYPES_LENGHT 4096
#define ERROR_STRING_LENGTH 2048
#define MAX_HEADER_SIZE 8192
#define HEADER_GROW_SIZE 1024
#define DEFAULT_IMAGE_TYPE "jpg"
#define MAX_LENGTH_COLUMN_NAME 255
#define MAX_STRING_NUMBER 255
#define MAX_LENGTH_COLUMN_TYPE 255
#define FOURD_OK 0
#define FOURD_ERROR 1
#define STATEMENT_BASE64 1
#define LOGIN_BASE64 1
#define PROTOCOL_VERSION "12.0"
#define PAGE_SIZE 100
#define OUTPUT_MODE "release"

typedef enum
{
	VK_UNKNOW=0,
	VK_BOOLEAN,
	VK_BYTE,
	VK_WORD,
	VK_LONG,
	VK_LONG8,
	VK_REAL,
	VK_FLOAT,
	VK_TIME,
	VK_TIMESTAMP,
	VK_DURATION,
	VK_TEXT,
	VK_STRING,
	VK_BLOB,
	VK_IMAGE
}FOURD_TYPE;

/******************************/
/* parse and format FOUR_TYPE */
/******************************/
FOURD_TYPE typeFromString(const char *type);
const char* stringFromType(FOURD_TYPE type);

/******************************************************************/
/* vk_sizeof                                                      */
/******************************************************************/
/* return sizeof type or -1 if varying length or 0 if unknow type */
/******************************************************************/
int vk_sizeof(FOURD_TYPE type);

/***************/
/* Result-Type */
/***************/
typedef enum
{
	UNKNOW=0,
	UPDATE_COUNT,
	RESULT_SET
}FOURD_RESULT_TYPE;
FOURD_RESULT_TYPE resultTypeFromString(const char *type);
const char* stringFromResultType(FOURD_RESULT_TYPE type);

/*********************/
/* Structure of VK_* */
/*********************/
typedef short FOURD_BOOLEAN;
typedef short FOURD_BYTE;
typedef short FOURD_WORD;
typedef int FOURD_LONG;
#ifdef WIN32
	typedef	__int64 FOURD_LONG8;
#else
	typedef long long FOURD_LONG8;
#endif
typedef	double FOURD_REAL;
typedef	struct{int exp;char sign;int data_length;void* data;}FOURD_FLOAT;
typedef	struct{short year;char mounth;char day;unsigned int milli;}FOURD_TIMESTAMP;
#ifdef WIN32
	typedef	__int64 FOURD_DURATION;//in milliseconds
#else
	typedef long long FOURD_DURATION;//in milliseconds
#endif
typedef struct{int length;unsigned char *data;}FOURD_STRING;
typedef struct{int length;void *data;}FOURD_BLOB;
typedef struct{int length;void *data;}FOURD_IMAGE;

typedef struct{
	/* Socket Win32 */
#ifdef WIN32
	WSADATA wsaData;
	SOCKET socket;
#else
	int socket;
#endif

	int init;		/*boolean*/
	int connected;	/*boolean*/

	/* status */
	int status;//1 OK, 0 KO
	FOURD_LONG8 error_code;
	char error_string[ERROR_STRING_LENGTH];

	/* updated row */
	FOURD_LONG8 updated_row;

	/*Command number used for*/
	/* LOGIN, STATEMENT, ETC*/
	unsigned int id_cnx;

	/* PREFERRED-IMAGE-TYPES */
	char *preferred_image_types;
	int timeout;

}FOURD;

typedef struct{
	FOURD_TYPE type;
	char null;//0 not null, 1 null
	void *pValue;
}FOURD_ELEMENT;

typedef struct{
	char sType[MAX_LENGTH_COLUMN_TYPE];
	FOURD_TYPE type;
	char sColumnName[MAX_LENGTH_COLUMN_NAME];
}FOURD_COLUMN;

typedef struct{
	unsigned int nbColumn;
	FOURD_COLUMN *Column;
}FOURD_ROW_TYPE;

typedef struct{
	FOURD *cnx;
	char *header;
	unsigned int header_size;

	/*state of statement (OK or KO)*/
	int status;	/*FOURD_OK or FOURD_ERRROR*/
	FOURD_LONG8 error_code;
	char error_string[ERROR_STRING_LENGTH];

	/*result of parse header
	  RESULT_SET for select
	  UPDATE_COUNT for insert, update, delete*/
	FOURD_RESULT_TYPE resultType;

	/*Id of statement used with 4D SQL-server*/
	int id_statement;
	/*Id of command use for request */
	int id_command;
	/*updateability is true or false */
	int updateability;

	/*total of row count */
	unsigned int row_count;

	/*row count in data buffer
	  for little select, row_count_sent = row_count
	  for big select, row_count_sent = 100 for the first result_set
	*/
	unsigned int row_count_sent;
	/*num of the first row
	for the first response in big select
	with default parametre on serveur : 0 */
	unsigned int first_row;

	/* row_type of this statement
	   containe column count, column name and column type*/
	FOURD_ROW_TYPE row_type;

	/*data*/
	FOURD_ELEMENT *elmt;

	/*current row index*/
	int numRow;
}FOURD_RESULT;

typedef struct {
	FOURD *cnx;
	char *query;	/*MAX_HEADER_SIZE is using because the query is insert into header*/
	unsigned int nb_element;
	unsigned int nbAllocElement;
	FOURD_ELEMENT *elmt;
	/* PREFERRED-IMAGE-TYPES */
	char *preferred_image_types;
}FOURD_STATEMENT;


FOURD* fourd_init(void);
int fourd_connect(FOURD *cnx,const char *host,const char *user,const char *password,const char *base,unsigned int port);
int fourd_close(FOURD *cnx);
int fourd_exec(FOURD *cnx,const char *query);
FOURD_LONG8 fourd_affected_rows(FOURD *cnx);

int fourd_errno(FOURD *cnx);
const char * fourd_error(FOURD *cnx);
const char * fourd_sqlstate(FOURD *cnx);
void fourd_free(FOURD* cnx);
void fourd_free_statement(FOURD_STATEMENT *state);
void fourd_timeout(FOURD* cnx,int timeout);

FOURD_LONG8 fourd_num_rows(FOURD_RESULT *result);
FOURD_RESULT *fourd_query(FOURD *cnx,const char *query);
int fourd_close_statement(FOURD_RESULT *res);
void fourd_free_result(FOURD_RESULT *res);


FOURD_LONG * fourd_field_long(FOURD_RESULT *res,unsigned int numCol);
FOURD_STRING * fourd_field_string(FOURD_RESULT *res,unsigned int numCol);
void * fourd_field(FOURD_RESULT *res,unsigned int numCol);
int fourd_next_row(FOURD_RESULT *res);

const char * fourd_get_column_name(FOURD_RESULT *res,unsigned int numCol);
FOURD_TYPE fourd_get_column_type(FOURD_RESULT *res,unsigned int numCol);
int fourd_num_columns(FOURD_RESULT *res);
int fourd_field_to_string(FOURD_RESULT *res,unsigned int numCol,char **value,size_t *len);

FOURD_STATEMENT * fourd_prepare_statement(FOURD *cnx,const char *query);
FOURD_STRING *fourd_create_string(char *param,int length);
int fourd_bind_param(FOURD_STATEMENT *state,unsigned int numParam,FOURD_TYPE type, void *val);
FOURD_RESULT *fourd_exec_statement(FOURD_STATEMENT *state, int res_size);

void fourd_set_preferred_image_types(FOURD* cnx,const char *types);
void fourd_set_statement_preferred_image_types(FOURD_STATEMENT *state,const char *types);
const char* fourd_get_preferred_image_types(FOURD* cnx);
const char* fourd_get_statement_preferred_image_types(FOURD_STATEMENT *state);
#endif
