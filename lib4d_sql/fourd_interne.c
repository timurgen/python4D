#include "fourd.h"
#include "fourd_int.h"
#include "base64.h"
#include "b64.h"
#include "utils.h"
#include <stdarg.h>

int Printf(const char* format,...)
{
#if VERBOSE
	va_list ap;
	va_start(ap,format);
	vprintf(format,ap);
#endif
	return 0;
}

int Printferr(const char* format,...)
{
#if VERBOSE
	va_list ap;
	va_start(ap,format);
	vfprintf(stderr,format,ap);
#endif
	return 0;
}

#ifndef WIN32
void ZeroMemory (void *s, size_t n)
{
	bzero(s,n);
}

int sprintf_s(char *buff,size_t size,const char* format,...)
{
	va_list ap;
	va_start(ap,format);
	vsnprintf(buff,size,format,ap);
	return 0;
}

int _snprintf_s(char *buff, size_t size, size_t count, const char *format,...)
{
	va_list ap;
	va_start(ap,format);
	vsnprintf(buff,((size>count)?count:size),format,ap);
	return 0;
}

int _snprintf(char *buff, int size, const char *format,...)
{
	va_list ap;
	va_start(ap,format);
	vsnprintf(buff,size,format,ap);
	return 0;
}
#endif

int dblogin(FOURD *cnx,unsigned int id_cnx,const char *user,const char*pwd,const char*image_type)
{
	char msg[MAX_HEADER_SIZE];
	FOURD_RESULT state;
	unsigned char *user_b64=NULL,*pwd_b64=NULL;
	//int len;
	_clear_atrr_cnx(cnx);

#if LOGIN_BASE64_ORIG
	//user_b64=base64_encode(user,strlen(user),&len);
	user_b64=b64_encode(user ,strlen(user));
	//pwd_b64=base64_encode(pwd,strlen(pwd),&len);
	pwd_b64=b64_encode(pwd,strlen(pwd));
	sprintf_s(msg,MAX_HEADER_SIZE,"%d LOGIN \r\nUSER-NAME-BASE64:%s\r\nUSER-PASSWORD-BASE64:%s\r\nPREFERRED-IMAGE-TYPES:%s\r\nREPLY-WITH-BASE64-TEXT:Y\r\nPROTOCOL-VERSION:%s\r\n\r\n",id_cnx,user_b64,pwd_b64,image_type,PROTOCOL_VERSION);
	Free(user_b64);
	Free(pwd_b64);
#else
	sprintf_s(msg,MAX_HEADER_SIZE,"%d LOGIN \r\nUSER-NAME:%s\r\nUSER-PASSWORD:%s\r\nPREFERRED-IMAGE-TYPES:%s\r\nREPLY-WITH-BASE64-TEXT:Y\r\nPROTOCOL-VERSION:%s\r\n\r\n",id_cnx,user,pwd,image_type,PROTOCOL_VERSION);
#endif

	socket_send(cnx,msg);

	if(receiv_check(cnx,&state)!=0)
		return 1;

	return 0;
}

int dblogout(FOURD *cnx,unsigned int id_cnx)
{
	char msg[MAX_HEADER_SIZE];
	FOURD_RESULT state;
	_clear_atrr_cnx(cnx);

	sprintf_s(msg,MAX_HEADER_SIZE,"%d LOGOUT\r\n\r\n",id_cnx);

	socket_send(cnx,msg);

	if(receiv_check(cnx,&state)!=0) {
		return 1;
	}

	return 0;
}

int quit(FOURD *cnx,unsigned int id_cnx)
{
	char msg[MAX_HEADER_SIZE];
	FOURD_RESULT state;
	_clear_atrr_cnx(cnx);

	sprintf_s(msg,MAX_HEADER_SIZE,"%d QUIT\r\n\r\n",id_cnx);

	socket_send(cnx,msg);

	if(receiv_check(cnx,&state)!=0) {
		return 1;
	}

	return 0;
}

int _query(FOURD *cnx,unsigned int id_cnx,const char *request,FOURD_RESULT *result,const char*image_type, int res_size)
{
	char *msg=NULL;
	FOURD_RESULT *res=NULL;

	int len;

	if (VERBOSE == 1)
		Printf("---Debug the _query\n");

	_clear_atrr_cnx(cnx);

	if(!_valid_query(cnx,request)) {
		return 1;
	}

	if(result!=NULL)
		res=result;
	else
		res=calloc(1,sizeof(FOURD_RESULT));

#if STATEMENT_BASE64
	unsigned char *request_b64=NULL;
	//request_b64=base64_encode(request,strlen(request),&len);
	request_b64=b64_encode(request,strlen(request));
	char *format_str="%d EXECUTE-STATEMENT\r\nSTATEMENT-BASE64:%s\r\nOutput-Mode:%s\r\nFIRST-PAGE-SIZE:%i\r\nPREFERRED-IMAGE-TYPES:%s\r\n\r\n";
	size_t buff_size=strlen(format_str)+strlen((const char *)request_b64)+42; //add some extra for the additional arguments and a bit more for good measure.
	msg=(char *)malloc(buff_size);
	snprintf(msg,buff_size,format_str,id_cnx,request_b64,OUTPUT_MODE,res_size,image_type);
	Free(request_b64);
#else
	char *format_str="%d EXECUTE-STATEMENT\r\nSTATEMENT:%s\r\nOutput-Mode:%s\r\nFIRST-PAGE-SIZE:%i\r\nPREFERRED-IMAGE-TYPES:%s\r\n\r\n";
	size_t buff_size=strlen(format_str)+strlen(request)+42; //add some extra for the additional arguments and a bit more for good measure.
	msg=(char *)malloc(buff_size);
	snprintf(msg, buff_size,format_str,id_cnx,request,OUTPUT_MODE,res_size,image_type);
#endif

	cnx->updated_row=-1;
	socket_send(cnx,msg);
	Free(msg);

	if(receiv_check(cnx,res)!=0)
		return 1;

	switch(res->resultType)	{
		case UPDATE_COUNT:
			//get Update-count: Nb row updated
			cnx->updated_row=-1;
			socket_receiv_update_count(cnx,res);
			_free_data_result(res);
			break;
		case RESULT_SET:
			//get data
			socket_receiv_data(cnx,res);
			cnx->updated_row=-1;
			if(result==NULL) {
				_free_data_result(res);
			}
			break;
		default:
			if (VERBOSE == 1)
				Printferr("Error: Result-Type not supported in query");
	}
	if(result==NULL) {
		Free(res);
	}

	if (VERBOSE == 1)
		Printf("---End of _query\n");

	return 0;
}

int _prepare_statement(FOURD *cnx,unsigned int id_cnx,const char *request)
{
	char *msg=NULL;
	FOURD_RESULT *res=calloc(1,sizeof(FOURD_RESULT));
	int len;

#if STATEMENT_BASE64
	unsigned char *request_b64=NULL;
	//request_b64=base64_encode(request,strlen(request),&len);
	request_b64=b64_encode(request,strlen(request));
	char *format_str="%d PREPARE-STATEMENT\r\nSTATEMENT-BASE64: %s\r\n\r\n";
	unsigned long buff_size=strlen(format_str)+strlen((const char *)request_b64)+2; //add some extra for good measure.
	msg=(char *)malloc(buff_size);
	snprintf(msg,buff_size,format_str,id_cnx,request_b64);
	Free(request_b64);
#else
	char *format_str="%d PREPARE-STATEMENT\r\nSTATEMENT: %s\r\n\r\n";
	unsigned long buff_size=strlen(format_str)+strlen(request)+2; //add some extra for good measure.
	msg=(char *)malloc(buff_size);
	snprintf(msg,buff_size,format_str,id_cnx,request);
#endif

	cnx->updated_row=-1;
	socket_send(cnx,msg);
	Free(msg);

	if(receiv_check(cnx,res)!=0)
		return 1;

	switch(res->resultType)	{
		case UPDATE_COUNT:
			//get Update-count: Nb row updated
			cnx->updated_row=-1;
			//socket_receiv_update_count(cnx,res);
			_free_data_result(res);
			break;
		case RESULT_SET:
			//get data
			socket_receiv_data(cnx,res);
			cnx->updated_row=-1;
			break;
		default:
			if (VERBOSE == 1)
				Printferr("Error: Result-Type not supported in query");
	}
	fourd_free_result(res);

	return 0;
}

int _query_param(FOURD *cnx,unsigned int id_cnx, const char *request,unsigned int nbParam, const FOURD_ELEMENT *param,FOURD_RESULT *result,const char*image_type,int res_size)
{
	char *msg=NULL;
	FOURD_RESULT *res=NULL;
	unsigned char *request_b64=NULL;
	int len;
	char *sParam=NULL;
	unsigned int i=0;
	char *data=NULL;
	unsigned int data_len=0;
	unsigned int size=0;

	if (VERBOSE == 1)
		Printf("---Debuging the _query_param\n");

	if(!_valid_query(cnx,request)) {
		return 1;
	}

	if(nbParam<=0)
		return _query(cnx,id_cnx,request,result,image_type,res_size);
	_clear_atrr_cnx(cnx);

	if(result!=NULL)
		res=result;
	else
		res=calloc(1,sizeof(FOURD_RESULT));


	/* construct param list */
	size_t paramlen=(nbParam+1)*13; //the longest type name is 12 characters, and we add a space between each parameter.
	// add a 1 to the number of parameters because I am paranoid.

	sParam=calloc(paramlen, sizeof(char)); //initalized to zero, so we should be able to call strlen() on it without problem

	for(i=0;i<nbParam;i++)
	{
		snprintf(sParam+strlen(sParam),paramlen-1-strlen(sParam)," %s",stringFromType(param[i].type));

		/* construct data */
		if(param[i].null==0) {
			data=realloc(data,++size);
			memset(data+(size-1),'1',1);
			data=_serialize(data,&size,param[i].type,param[i].pValue);
		} else {
			if (VERBOSE == 1)
				Printf("Serialize a null value\n");

			data=realloc(data,++size);
			memset(data+(size-1),'0',1);
		}
	}

	data_len=size;
	/* construct Header */
#if STATEMENT_BASE64
	//request_b64=base64_encode(request,strlen(request),&len);
	request_b64=b64_encode(request,strlen(request));
	char *msg_format="%d EXECUTE-STATEMENT\r\nSTATEMENT-BASE64:%s\r\nOutput-Mode:%s\r\nFIRST-PAGE-SIZE:%i\r\nPREFERRED-IMAGE-TYPES:%s\r\nPARAMETER-TYPES:%s\r\n\r\n";
	size_t msg_length=strlen((const char *)request_b64)+strlen(msg_format)+strlen(image_type)+strlen(sParam)+20;
	msg=malloc(msg_length);
	snprintf(msg,msg_length,msg_format,id_cnx,request_b64,"release",res_size,image_type,sParam);
	Free(request_b64);
#else
	char *msg_format="%d EXECUTE-STATEMENT\r\nSTATEMENT:%s\r\nOutput-Mode:%s\r\nFIRST-PAGE-SIZE:%i\r\nPREFERRED-IMAGE-TYPES:%s\r\nPARAMETER-TYPES:%s\r\n\r\n";
	size_t msg_length=strlen(request)+strlen(msg_format)+strlen(image_type)+strlen(sParam)+20;
	msg=malloc(msg_length);
	snprintf(msg,msg_length,msg_format,id_cnx,request,"release",res_size,image_type,sParam);
#endif

	Free(sParam);

	socket_send(cnx,msg);
	Free(msg);

	socket_send_data(cnx,data,data_len);
	//done with the data object, free it
	if(data!=NULL)
		free(data);

	if(receiv_check(cnx,res)!=0){
		return 1;
	}

	switch(res->resultType)	{
		case UPDATE_COUNT:
			//get Update-count: Nb row updated
			socket_receiv_update_count(cnx,res);
			_free_data_result(res);
			break;
		case RESULT_SET:
			//get data
			socket_receiv_data(cnx,res);
			cnx->updated_row=-1;
			if(result==NULL) {
				_free_data_result(res);
			}
			break;
		default:
			if (VERBOSE == 1)
				Printferr("Error: Result-Type not supported in query");
	}

	if(result==NULL)
		Free(res);
	return 0;
}

/* low level commande 
   command_index and statement_id is identify by result of execute statement commande */
int __fetch_result(FOURD *cnx,unsigned int id_cnx,int statement_id,int command_index,unsigned int first_row,unsigned int last_row,FOURD_RESULT *result)
{
	char msg[MAX_HEADER_SIZE];

	_clear_atrr_cnx(cnx);

	if(result==NULL) {
		return 0;
	}
	sprintf_s(msg,MAX_HEADER_SIZE,"%d FETCH-RESULT\r\nSTATEMENT-ID:%d\r\nCOMMAND-INDEX:%03d\r\nFIRST-ROW-INDEX:%d\r\nLAST-ROW-INDEX:%d\r\nOutput-Mode:%s\r\n\r\n",id_cnx,statement_id,command_index,first_row,last_row,"release");

	socket_send(cnx,msg);

	if(receiv_check(cnx,result)!=0)
		return 1;

	socket_receiv_data(cnx,result);

	return 0;
}

/*get next row set in result_set*/
int _fetch_result(FOURD_RESULT *res,unsigned int id_cnx)
{
	FOURD *cnx=res->cnx;
	FOURD_RESULT *nRes=NULL;
	void *last_data=NULL;
	//int id_statement=res->id_statement;

	unsigned int first_row=res->first_row+res->row_count_sent;
	unsigned int last_row=res->first_row+res->row_count_sent+(PAGE_SIZE-1);
	if(last_row>=res->row_count) {
		last_row=res->row_count-1;
	}

	nRes=calloc(1,sizeof(FOURD_RESULT));
	_clear_atrr_cnx(cnx);

	/*set paramaters unsed in socket_receiv */
	nRes->first_row=first_row;
	nRes->row_count_sent=last_row-first_row+1;
	nRes->cnx=res->cnx;
	nRes->row_type=res->row_type;
	nRes->updateability=res->updateability;

	/*get new Result set in new FOURD_RESULT*/
	cnx->id_cnx++;
	if(__fetch_result(cnx,cnx->id_cnx,res->id_statement,0,first_row,last_row,nRes)){
		return 1;
	}
	/*switch data between res and nRes FOURD_RESULT*/
	last_data=res->elmt;
	res->elmt=nRes->elmt;
	nRes->elmt=last_data;	/*important for free memory after */
	res->first_row=first_row;
	res->row_count_sent=last_row-first_row+1;
	res->error_code=nRes->error_code;
	sprintf_s(res->error_string,sizeof(res->error_string),"%s",nRes->error_string);
	res->status=nRes->status;


	/*free memory */
	_free_data_result(nRes);
	Free(nRes);

	return 0;

}

int close_statement(FOURD_RESULT *res,unsigned int id_cnx)
{
	char msg[MAX_HEADER_SIZE];
	FOURD *cnx=NULL;
	FOURD_RESULT state;

	if(res==NULL)
		return 0;
	cnx=res->cnx;
	_clear_atrr_cnx(cnx);
	sprintf_s(msg,MAX_HEADER_SIZE,"%d CLOSE-STATEMENT\r\nSTATEMENT-ID:%d\r\n\r\n",id_cnx,res->id_statement);

	socket_send(cnx,msg);

	if(receiv_check(cnx,&state)!=0) {
		return 1;
	}
	return 0;
}

int get(const char* msg,const char* section,char *value,int max_length)
{
	char *loc=NULL;
	char *fin=NULL;
	loc=strstr(msg,section);
	if(loc==NULL) {
		return -1;
	}
	loc+=strlen(section);
	loc=strstr(loc,":");
	if(loc==NULL) {
		return -1;
	}
	loc++;
	fin=strstr(loc,"\n");
	if(fin==NULL) {
		return -1;
	}
	if(*(fin-1)=='\r') {
#ifdef WIN32
		fin--;
#endif
	}

	_snprintf_s(value,max_length,fin-loc,"%s",loc);
	value[fin-loc]=0;

	if(strstr(section,"-Base64")!=NULL) {
		//decode la valeur
		unsigned char *value_decode=NULL;
		int len_dec=0;
		//value_decode=base64_decode(value,strlen(value),&len_dec);
		value_decode=b64_decode(value,strlen(value));
		len_dec=strlen(value_decode);
		value_decode[len_dec]=0;
		strncpy_s(value,max_length,(const char*)value_decode,(size_t)len_dec);
		value[len_dec]=0;
		Free(value_decode);
	}
	return 0;
}

FOURD_LONG8 _get_status(const char *header,int *status, FOURD_LONG8 *error_code,char *error_string)
{
	char *loc=NULL,*fin=NULL,sStatus[50];
	*status=FOURD_ERROR;
	loc=strstr(header," ");
	if(loc==NULL) {
		return -1;
	}
	loc++;
	fin=strstr(loc,"\n");
	if(fin==NULL) {
		return -1;
	}
	if(*(fin-1)=='\r') {
#ifdef WIN32
		fin--;
#endif
	}
	_snprintf_s(sStatus,50,fin-loc,"%s",loc);
	status[fin-loc]=0;
	if(strcmp(sStatus,"OK")==0) {
		//it's ok
		*error_code=0;
		error_string[0]=0;
		*status=FOURD_OK;
		return 0;
	}
	else {
		//there is an error
		*status=FOURD_ERROR;
		{
			char error[50];
			get(header,"Error-Code",error,50);
			*error_code=atoi(error);
		}
		get(header,"Error-Description",error_string,ERROR_STRING_LENGTH);
		return *error_code;
	}
	return -1;
}

void _alias_str_replace(char *list_alias)
{
	char *loc=list_alias;
	char *locm=NULL;
	while((loc=strstr(loc,"] ["))!=NULL) {
		if((loc-list_alias)>1) {
			locm=loc;
			locm--;
			if(locm[0]!=']') {
				loc[1]='\r';
			}
			else {
				loc++;
			}
		}
		else {
			loc[1]='\r';
		}
	}
}

int treate_header_response(FOURD_RESULT* state)
{
	char *header=state->header;
	FOURD_LONG8 ret_get_status=0;

	//get status in the header
	state->elmt=0;
	ret_get_status=_get_status(state->header,&(state->status),&(state->error_code),state->error_string);
	if(ret_get_status<0) {
		//Technical error in parse header status
		return 1;
	}
	else if(ret_get_status>0) {
		//The header is error-header
		//nothing to do with error-header
		return 1;
	}
	//The header is ok-header
	//get Column-Count
	{
		char column_count[MAX_STRING_NUMBER];
		if(get(header,"Column-Count",column_count,MAX_STRING_NUMBER)==0) {
			state->row_type.nbColumn=(unsigned int) atoi(column_count);
			//memory allocate for column name and column type
			state->row_type.Column=calloc(state->row_type.nbColumn,sizeof(FOURD_COLUMN));

			if (VERBOSE == 1)
				Printf("Column-Count:%d\n",state->row_type.nbColumn);
		}
	}
	//get Column-Types
	{
		char column_type[MAX_COL_TYPES_LENGHT];
		char *column=NULL;
		unsigned int num=0;
		//char *context=NULL;
		if(get(header,"Column-Types",column_type,MAX_COL_TYPES_LENGHT)==0) {

			if (VERBOSE == 1)
				Printf("Column-Types => '%s'\n",column_type);

			column = strtok_s(column_type, " ",&context);
			if(column!=NULL)
				do{

					if (VERBOSE == 1)
						Printf("Column %d: %s (%s)\n",num+1,column,stringFromType(typeFromString(column)));

					if(num<state->row_type.nbColumn) {
						state->row_type.Column[num].type=typeFromString(column);
						strncpy_s(state->row_type.Column[num].sType,MAX_COL_TYPES_LENGHT,column,strlen(column)+1);
					}
					else {
						if (VERBOSE == 1)
							Printf("Error: There is more columns than Column-Count\n");
					}
					num++;
					column = strtok_s(NULL, " ",&context);
				}while(column!=NULL);

			if (VERBOSE == 1)
				Printf("End of reading columns\n");
		}
	}
	//get Column-Aliases-Base64
	{
		char *column_alias;char *alias=NULL;
		unsigned int num=0;
		char * col_start;
		char * col_fin;
		long base64_size=MAX_COL_TYPES_LENGHT;
		char *section="Column-Aliases-Base64";

		//Figure out the length of our section. fun with pointers!
		//Start by getting a pointer to the start of the section label
		col_start=strstr(header,section);
		if(col_start!=NULL){
			//advance the pointer by the length of the section label
			col_start+=strlen(section);
			//and find the first : (probably the next character)
			col_start=strstr(col_start,":");

			if(col_start!=NULL){
				//after making sure we still have something to work with,
				//advance to the next character after the ":", which is the
				//start of our data
				col_start++;

				//now find the end. It should have a new line after it
				col_fin=strstr(col_start,"\n");
				if(col_fin!=NULL){
					//we have pointers to the start and end of our data. So how long is it?
					//just subtract the pointers!
					base64_size=col_fin-col_start;
				}
			}
		}
		//if we ran into any issues with the above manipulation, we just use the
		//default size of 2048 and pray it works :)
		column_alias=calloc(sizeof(char), base64_size+5); //I always like to give a few bytes wiggle

		//char *context=NULL;
		if(get(header,"Column-Aliases-Base64",column_alias,base64_size)==0) {
			/* delete the last espace char if exist */
			if(column_alias[strlen(column_alias)-1]==' ') {
				column_alias[strlen(column_alias)-1]=0;
			}

			if (VERBOSE == 1)
				Printf("Column-Aliases-Base64 => '%s'\n",column_alias);

			_alias_str_replace(column_alias);
			alias = strtok_s(column_alias, "\r",&context);
			if(alias!=NULL)
				do{
					if (VERBOSE == 1)
						Printf("Alias %d: '%s'\n",num+1,alias);

					if(num<state->row_type.nbColumn) {
						/* erase [] */
						if(*alias=='[' && alias[strlen(alias)-1]==']') {
							strncpy_s(state->row_type.Column[num].sColumnName,MAX_COL_TYPES_LENGHT,alias+1,strlen(alias)-2);
						} else {
							strncpy_s(state->row_type.Column[num].sColumnName,MAX_COL_TYPES_LENGHT,alias,strlen(alias));
						}
					}else {
						if (VERBOSE == 1)
							Printf("Error: There is more alias than Column-Count\n");
					}
					num++;
					alias = strtok_s(NULL, "\r",&context);
				}while(alias!=NULL);

			if (VERBOSE == 1)
				Printf("End reading alias\n");
		}
		free(column_alias);
	}
	//get Row-Count
	{
		char row_count[MAX_STRING_NUMBER];
		if(get(header,"Row-Count",row_count,MAX_STRING_NUMBER)==0) {
			state->row_count=(unsigned int) atoi(row_count);

			if (VERBOSE == 1)
				Printf("Row-Count:%d\n",state->row_count);
		}
	}
	//get Row-Count-Sent
	{
		char row_count[MAX_STRING_NUMBER];
		if(get(header,"Row-Count-Sent",row_count,MAX_STRING_NUMBER)==0) {

			if (VERBOSE == 1)
				Printf("Row-Count-Sent:\"%s\" <=lut\n",row_count);

			state->row_count_sent=(unsigned int) atoi(row_count);

			if (VERBOSE == 1)
				Printf("Row-Count-Sent:%d\n",state->row_count_sent);
		}
	}
	//get Statement-ID
	{
		char statement_id[MAX_STRING_NUMBER];
		if(get(header,"Statement-ID",statement_id,MAX_STRING_NUMBER)==0) {
			state->id_statement=atoi(statement_id);

			if (VERBOSE == 1)
				Printf("Statement-ID:%d\n",state->id_statement);
		}
	}
	//Column-Updateability
	{
		char updateability[MAX_COL_TYPES_LENGHT];
		//state->updateability=1;
		if(get(header,"Column-Updateability",updateability,MAX_COL_TYPES_LENGHT)==0) {
			state->updateability=(strstr(updateability,"Y")!=NULL);

			if (VERBOSE == 1)
			{
				Printf("Column-Updateability:%s\n",updateability);
				Printf("Column-Updateability:%d\n",state->updateability);
			}
		}
	}
	//get Result-Type
	{
		char result_type[MAX_COL_TYPES_LENGHT];
		if(get(header,"Result-Type",result_type,MAX_COL_TYPES_LENGHT)==0) {
			strstrip(result_type);
			//if Result-Type containt more than 1 Result-type => multirequete => not supproted by this driver
			if(strstr(result_type," ")!=NULL)
			{
				//multiquery not supported by this driver

				if (VERBOSE == 1)
				{
					Printf("Result-Type:'%s'\n",result_type);
					Printf("Position %d\n",strstr(result_type," ")-result_type);
					Printferr("Error: Multiquery not supported\n");
				}

				return 1;
			}
			state->resultType=resultTypeFromString(result_type);
			switch(state->resultType) {
				case UPDATE_COUNT:
					break;
				case RESULT_SET:
					break;
				case UNKNOW:
				default:
					if (VERBOSE == 1)
						Printf("Error: %d Result-Type not supported",result_type);
					break;
			}
		}
	}
	return 0;
}

int receiv_check(FOURD *cnx,FOURD_RESULT *state)
{
	socket_receiv_header(cnx,state);

	if(treate_header_response(state)!=0) {
		if (VERBOSE == 1)
			Printferr("Error in treate_header_response\n");

		cnx->status=state->status;
		cnx->error_code=state->error_code;
		//_snprintf_s(cnx->error_string,ERROR_STRING_LENGTH,strlen(state->error_string),"%s",state->error_string);
		_snprintf(cnx->error_string,ERROR_STRING_LENGTH,"%s",state->error_string);
		//strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,state->error_string,strlen(state->error_string));
		//printf("treate_header_response return 1=> une erreur\n");
		return 1;
	}
	cnx->status=state->status;
	cnx->error_code=state->error_code;
	strncpy_s(cnx->error_string,ERROR_STRING_LENGTH,state->error_string,ERROR_STRING_LENGTH);
	return 0;
}

void _clear_atrr_cnx(FOURD *cnx)
{
	cnx->error_code=0L;
	strcpy_s(cnx->error_string,ERROR_STRING_LENGTH,"");
	cnx->updated_row=0L;
}

void _free_data_result(FOURD_RESULT *res)
{
	//res->elmt
	unsigned int nbCol=res->row_type.nbColumn;
	unsigned int nbRow=res->row_count_sent;
	unsigned int nbElmt=nbCol*nbRow;
	unsigned int i=0;
	FOURD_ELEMENT *pElmt=res->elmt;
	if(pElmt==NULL) {
		return;
	}
	for(i=0;i<nbElmt;i++,pElmt++)
	{
		switch(pElmt->type) {
			case VK_BOOLEAN:
			case VK_BYTE:
			case VK_WORD:
			case VK_LONG:
			case VK_LONG8:
			case VK_REAL:
			case VK_DURATION:
			case VK_TIMESTAMP:
				Free(pElmt->pValue);
				break;
			case VK_FLOAT:
				FreeFloat((FOURD_FLOAT *)pElmt->pValue);
				break;
			case VK_STRING:
				FreeString((FOURD_STRING *)pElmt->pValue);
				break;
			case VK_BLOB:
				FreeBlob((FOURD_BLOB *)pElmt->pValue);
				break;
			case VK_IMAGE:
				FreeImage((FOURD_IMAGE *)pElmt->pValue);
				break;
			default:
				break;
		}
	}

	Free(res->elmt);
}

void *_copy(FOURD_TYPE type,void *org)
{
	void *buff=NULL;
	//int size=0;
	if(org!=NULL)
	{
		switch(type) {
			case VK_BOOLEAN:
			case VK_BYTE:
			case VK_WORD:
			case VK_LONG:
				if (VERBOSE == 1)
					Printf("*******Bind %d ********\n",*(FOURD_LONG*)org);
			case VK_LONG8:
			case VK_REAL:
			case VK_DURATION:
			case VK_TIMESTAMP:
				buff=calloc(1,(size_t)vk_sizeof(type));
				memcpy(buff,org,vk_sizeof(type));
				break;
			case VK_FLOAT:
			{
				FOURD_FLOAT *f=org;
				FOURD_FLOAT *cp=NULL;
				cp=calloc(1,sizeof(FOURD_FLOAT));
				cp->data=calloc(1,(size_t)f->data_length);
				cp->exp=f->exp;
				cp->sign=f->sign;
				cp->data_length=f->data_length;
				memcpy(cp->data,f->data,f->data_length);
				buff=cp;
			}
				break;
			case VK_STRING:
			{
				FOURD_STRING *src=org;
				FOURD_STRING *cp=NULL;
				cp=calloc(1,sizeof(FOURD_STRING));
				cp->data=calloc((size_t)src->length,2);	/* 2 bytes per char */
				cp->length=src->length;
				memcpy(cp->data,src->data,src->length*2);  /* 2 bytes per char */
				buff=cp;
			}
				break;
			case VK_BLOB:
			{
				FOURD_BLOB *src=org;
				FOURD_BLOB *cp=NULL;
				cp=calloc(1,sizeof(FOURD_BLOB));
				cp->data=calloc((size_t)src->length,1);
				cp->length=src->length;
				memcpy(cp->data,src->data,src->length);
				buff=cp;
			}
				break;
			case VK_IMAGE:
			{
				FOURD_IMAGE *src=org;
				FOURD_IMAGE *cp=NULL;
				cp=calloc(1,sizeof(FOURD_IMAGE));
				cp->data=calloc((size_t)src->length,1);
				cp->length=src->length;
				memcpy(cp->data,src->data,src->length);
				buff=cp;
				break;
			}
				break;
			default:
				break;
		}
	}
	return buff;
}

char *_serialize(char *data,unsigned int *size, FOURD_TYPE type, void *pObj)
{
	int lSize=0;
	if(pObj!=NULL) {
		switch(type) {
			case VK_BOOLEAN:
			case VK_BYTE:
			case VK_WORD:
			case VK_LONG:
				if (VERBOSE == 1)
					Printf("*******Serialize %d ********\n",*(FOURD_LONG*)pObj);
			case VK_LONG8:
			case VK_REAL:
			case VK_DURATION:
				lSize=vk_sizeof(type);
				data=realloc(data,(*size)+lSize);
				memcpy(data+*size,pObj,lSize);
				*size+=lSize;
				break;
			case VK_TIMESTAMP:/* Use other procedure for serialize this one because structure can align */
			{
				FOURD_TIMESTAMP *o=pObj;
				lSize=sizeof(o->year)+sizeof(o->mounth)+sizeof(o->day)+sizeof(o->milli);
				data=realloc(data,(*size)+lSize);
				memcpy(data+*size,&(o->year),2);
				memcpy(data+*size+2,&(o->year),1);
				memcpy(data+*size+3,&(o->year),1);
				memcpy(data+*size+4,&(o->year),4);
				*size+=lSize;
			}
				break;
			case VK_FLOAT:
			{
				FOURD_FLOAT *o=pObj;
				lSize=sizeof(o->exp)+sizeof(o->sign)+sizeof(o->data_length)+o->data_length;
				data=realloc(data,(*size)+lSize);
				memcpy(data+*size,&(o->exp),4);
				memcpy(data+*size+4,&(o->sign),1);
				memcpy(data+*size+5,&(o->data_length),4);
				memcpy(data+*size+9,o->data,o->data_length);
				*size+=lSize;
			}
				break;
			case VK_STRING:
			{
				FOURD_STRING *o=pObj;
				int len=o->length;
				len=-len;
				lSize=sizeof(o->length)+o->length*2;
				data=realloc(data,(*size)+lSize);
				memcpy(data+*size,&len,4);
				memcpy(data+*size+4,o->data,o->length*2);
				*size+=lSize;
			}
				break;
			case VK_BLOB:
			{
				FOURD_BLOB *o=pObj;
				lSize=sizeof(o->length)+o->length*2;
				data=realloc(data,(*size)+lSize);
				memcpy(data+*size,&(o->length),4);
				memcpy(data+*size+4,o->data,o->length*2);
				*size+=lSize;
			}
				break;
			case VK_IMAGE:
			{
				FOURD_IMAGE *o=pObj;
				lSize=sizeof(o->length)+o->length*2;
				data=realloc(data,(*size)+lSize);
				memcpy(data+*size,&(o->length),4);
				memcpy(data+*size+4,o->data,o->length*2);
				*size+=lSize;
			}
				break;
			default:
				break;
		}
	}
	return data;
}

void Free(void *p)
{
	if(p)
	{
		free(p);
		p=NULL;
	}
}

void FreeFloat(FOURD_FLOAT *p)
{
	if(p) {
		Free(p->data);
		Free(p);
	}
}

void FreeString(FOURD_STRING *p)
{
	if(p) {
		Free(p->data);
		Free(p);
	}
}

void FreeBlob(FOURD_BLOB *p)
{
	if(p) {
		Free(p->data);
		Free(p);
	}
}

void FreeImage(FOURD_IMAGE *p)
{
	if(p) {
		Free(p->data);
		Free(p);
	}
}

void PrintData(const void *data,unsigned int size)
{
	const char *d=data;
	unsigned int i=0;
	if(size>=1)
		if (VERBOSE == 1)
			Printf("0x%X",*(char *)(d+i));
	for(i=1;i<size;i++) {
		if (VERBOSE == 1)
			Printf(" 0x%X",*(char *)(d+i));
	}
}

int _is_multi_query(const char *request)
{
	int i=0;
	size_t len;
	int inCol=0;
	int inStr=0;
	int finFirst=0;
	char car=0;
	if(request==NULL){
		return 0;
	}
	len=strlen(request);
	if(len<1){
		return 0;
	}
	for(i=0;i<len;i++){

		car=request[i];
		switch(car){
			case '[':
				/* start of 4D object name */
				if(!inStr){
					if(!inCol){
						/* printf("["); */
						inCol=1;
					}
					else {
						/* printf("_"); */
					}
				}else {
					/* printf("s"); */
				}
				break;
			case ']':
				if(inStr){
					/* printf("s"); */
				}else if(inCol){
					inCol=0;
					/* printf("]"); */
				}else {
					if(i>1){ /* check the previous charactere */
						if(request[i-1]==']'){
							/* not end of colomn name */
							inCol=1;
							/* printf("-"); */
						}else {
							inCol=0;
							/* printf("]"); */
						}
					}else {
						/* printf("_");*/
					}
				}

				break;
			case '\'':
				if(!inCol){
					/* printf("'");*/
					if(inStr==0){
						inStr=1;
					}else{
						inStr=0;
					}
				}else{
					/* printf("c"); */
				}
				break;
			case ';':
				/* end of query */
				if(!inCol && !inStr){
					finFirst=1;
					/* printf(";");*/
				}else {
					/*printf("_");*/
				}
				break;
			default:
				if(inCol){
					/* printf("C"); */
				}
				else if(inStr){
					/* printf("S"); */
				}
				else if(car==' '){
					/*printf(" ");*/
				}else{
					if(finFirst){
						/* printf("X"); */
						return 1;
					}else {
						/* printf("*"); */
					}
				}
				break;
		}

	}
	return 0;
}

int _valid_query(FOURD *cnx,const char *request)
{
	if(_is_multi_query(request)){
		cnx->error_code=-5001;
		sprintf_s(cnx->error_string,ERROR_STRING_LENGTH,"MultiQuery not supported",ERROR_STRING_LENGTH);
		return 0;
	}
	return 1;
}
