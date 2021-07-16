#include <stdint.h>
#include <stdlib.h>
//#include <unistd.h>
#include<windows.h>
#include<shellapi.h>

#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <sys/types.h>
#include "aes.h"

/*
데이터 비교용 
memcmp(string.h) 함수를 사용할 수 있다면 대체해도 됨.
*/
int myMemcmp(const void *s1, const void *s2, size_t n)
{       
    const unsigned char *su1 = (const unsigned char *)s1;
    const unsigned char *su2 = (const unsigned char *)s2;

    for (; 0 < n; ++su1, ++su2, --n)
      if (*su1 != *su2)
        return (*su1 < *su2 ? -1 : +1);
    return (0);
}
int dumpkey(const char *s, int len)
{
    printf("Key -");
    for (int i = 0; i < len; i++)
    {
        printf("0x%02X, ", (0xFF & s[i]));
    }
    printf("\t");
}

int dumpdata(const char *s, int len)
{
    printf("Data -");
    for (int i = 0; i < len; i++)
    {
        printf("0x%02X, ", (0xFF & s[i]));
    }
    printf("\n");
    fflush(stdout);
}
int dump(const char *s, int len)
{
    //printf("len = %d\n", len);
    for (int i = 0; i < len; i++)
    {
        printf("0x%02X, ", (0xFF & s[i]));
        if((i + 1)% 16 == 0)
            printf("\n");
    }
    printf("\n");
}



//복호화 테스트 함수
long getHex(char* hex){
    long rtnVal;
    char end[4];
    char *pEnd = end;

    rtnVal = strtol(hex, &pEnd, 16);
    return rtnVal;
}

void fnStr2Hex(char* out, char* in){
    int idx;
    int outIdx = 0;
    char hex[3];
    int len = strlen(in);

    for(idx=0; idx < len; idx+=2){
        strncpy(hex, in+idx, 2);
        out[outIdx++] = getHex(hex);
    }
}

#define Max_KEY_len  (16)
#define Max_data_len  ( (Max_KEY_len * 188))


uint8_t iv[Max_KEY_len]; // = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t key[Max_KEY_len];// = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t in[Max_data_len]; 
uint8_t out[Max_data_len];
uint8_t inConv[Max_data_len];  

//#define ffp_msg(fmt, ...) {    printf(fmt, __VA_ARGS__);    fflush(stdout); }
#define ffp_msg(fmt,args...) { printf (fmt,## args); fflush(stdout);  }

#define DBG_MSG 0
static int test_decrypt_cbc(char * argv[])
{
    char source[Max_data_len];
    int8_t data[Max_data_len];
    FILE *fptr;

    char temp[10];

#if defined(__linux__)

    //   if ((fptr = fopen("/home/conun_docker/data.txt", "r")) == NULL)
    //    {
    //        if ((fptr = fopen("/home/conun_docker/provider_path/data.txt", "r")) == NULL)
    //        {
    //            if ((fptr = fopen("./data.txt", "r")) == NULL)
    //            {
    //                ffp_msg("Error! opening file");
    //                // Program exits if the file pointer returns NULL.
    //                return 0;
    //            }
    //        }
    //     }
    strcpy(source, pdata);
#else

#if DBG_MSG
    ffp_msg("start opening file\n");
#endif
    char strBuffer[_MAX_PATH] = {
        0,
    };
    char *pstrBuffer = NULL;

    pstrBuffer = getcwd(strBuffer, _MAX_PATH);
    ffp_msg(pstrBuffer);
    ffp_msg("\n");

    if ((fptr = fopen(".\\data.txt", "r")) == NULL)
    {
        ffp_msg("Error! opening file");
        // Program exits if the file pointer returns NULL.
        return 0;
    }
    fscanf(fptr, "%s", source);

    fclose(fptr);
#endif

#if DBG_MSG
    ffp_msg("succeed opening file\n");
#endif

    int len = strlen(source) / 2;
#if DBG_MSG
    ffp_msg("read file len(%d)\n", len);
#endif

    if (len < 16)
    {
        ffp_msg("Error! opening file\n");
        return 0;
    }
    fnStr2Hex(data, source);
#if DBG_MSG
    dump(data, len);
#endif

    len = 0;
    //mode
    memset(temp, 0, sizeof(temp));
    memcpy(temp, data + len, 1);
    int mode = temp[0];
    len += 1;

    //keylen
    memset(temp, 0, sizeof(temp));
    memcpy(temp, data + len, 2);
    int keylen = ((0xFF & temp[0]) << 8) + ((0xFF & temp[1]) << 0);
    len += 2;
#if DBG_MSG
    ffp_msg("keylen  : %d\n", keylen);
#endif

    //plaintextlen
    memset(temp, 0, sizeof(temp));
    memcpy(temp, data + len, 2);
    int plaintextlen = ((0xFF & temp[0]) << 8) + ((0xFF & temp[1]) << 0);
    if (plaintextlen < 1)
    {
        ffp_msg("error plaintextlen  : %d\n", plaintextlen);
        return 0;
    }
    len += 2;
#if DBG_MSG
    ffp_msg("plaintextlen  :%d, %x, %d\n", temp[0], temp[1], plaintextlen);
#endif
    //enlevel
    memset(temp, 0, sizeof(temp));
    memcpy(temp, data + len, 1);
    int enlevel = (0xFF & (temp[0]));
    len += 1;
#if DBG_MSG
    ffp_msg("enlevel  : %d\n", enlevel);
#endif
    //copy IV
    memcpy(iv, data + len, keylen);
    len += keylen;

    //copy KEY
    memcpy(key, data + len, keylen);
    len += keylen;

    //copy plain text
    memcpy(in, data + len, plaintextlen);
    len += plaintextlen;
    //copy out put
    memcpy(out, data + len, plaintextlen);
    len += plaintextlen;

    time_t rawtime, start, end;
    clock_t t1, t2;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
#if DBG_MSG
    ffp_msg("Start Time : %s", asctime(timeinfo));
#endif
    //암호화 키 공개키 고정값

    uint8_t result[Max_data_len];

    //aes 구조체
    struct AES_ctx ctx;
#if DBG_MSG
    ffp_msg("CBC decrypt key : \n");
    dump(key, keylen);
    ffp_msg("Plain Text : \n");
    dump(in, plaintextlen);
    ffp_msg("CBC decrypt Plain Text : \n");
    dump(out, plaintextlen);
#endif

    int n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, n12, n13, n14, n15, n16;

    int index = atoi(argv[1]);
    int totalcount = atoi(argv[2]);
    int rangecount = (256 / totalcount);
    int modcount = (256 % totalcount);
    int startindex;
    int endindex;
    int processrate = 0;
    double totcount = 0, donecount = 0;
    int keyindex = keylen - 16;

    if (index < modcount)
    {
        startindex = (index * rangecount) + (index);
        endindex = (startindex + rangecount);
    }
    else
    {
        startindex = (index * rangecount) + modcount;
        endindex = startindex + (rangecount - 1);
    }

    if ((endindex > 255) && (startindex > 255))
    {
        ffp_msg("Erro : Please check start index and count %d,  %d\n", index, totalcount);
        return 0;
    }
    if (endindex > 255)
        endindex = 255;

#if 1 //DBG_MSG
    ffp_msg("Info : start index and end index (%d, %d) : count(%d), range(%d)\n", startindex, endindex, (endindex - startindex) + 1, rangecount);
#endif

    if (mode)
    {
#if DBG_MSG
        ffp_msg("Release mode decrypt(key len : %d, plain text len : %d\n", keylen, plaintextlen);
#endif

        totcount = (endindex - startindex + 1) * pow(256, 15);

        for (n1 = startindex; n1 < endindex; n1++)
        {
            for (n2 = 0; n2 <= 0xff; n2++)
            {
                for (n3 = 0; n3 <= 0xff; n3++)
                {
                    for (n4 = 0; n4 <= 0xff; n4++)
                    {
                        for (n5 = 0; n5 <= 0xff; n5++)
                        {
                            for (n6 = 0; n6 <= 0xff; n6++)
                            {
                                for (n7 = 0; n7 <= 0xff; n7++)
                                {
                                    for (n8 = 0; n8 <= 0xff; n8++)
                                    {
                                        for (n9 = 0; n9 <= 0xff; n9++)
                                        {
                                            for (n10 = 0; n10 <= 0xff; n10++)
                                            {
                                                for (n11 = 0; n11 <= 0xff; n11++)
                                                {
                                                    for (n12 = 0; n12 <= 0xff; n12++)
                                                    {
                                                        for (n13 = 0; n13 <= 0xff; n13++)
                                                        {
                                                            t1 = clock();
                                                            for (n14 = 0; n14 <= 0xff; n14++)
                                                            {
                                                                for (n15 = 0; n15 <= 0xff; n15++)
                                                                {
                                                                    for (n16 = 0; n16 <= 0xff; n16++)
                                                                    {

                                                                        key[keyindex + 0] = n1;
                                                                        key[keyindex + 1] = n2;
                                                                        key[keyindex + 2] = n3;
                                                                        key[keyindex + 3] = n4;
                                                                        key[keyindex + 4] = n5;
                                                                        key[keyindex + 5] = n6;
                                                                        key[10] = n1;
                                                                        key[keyindex + 6] = n7;
                                                                        key[keyindex + 7] = n8;
                                                                        key[keyindex + 8] = n9;
                                                                        key[keyindex + 9] = n10;
                                                                        key[keyindex + 10] = n11;
                                                                        key[10] = n1;
                                                                        key[keyindex + 11] = n1;
                                                                        key[keyindex + 12] = n13;
                                                                        key[keyindex + 13] = n14;
                                                                        key[keyindex + 14] = n15;
                                                                        key[keyindex + 15] = n16;

                                                                        AES_ctx_set_iv(&ctx, iv);
                                                                        AES_init_ctx(&ctx, key);

                                                                        AES_CBC_decrypt_bufferEx(&ctx, out, result, plaintextlen);

                                                                        donecount++;

                                                                        // ffp_msg("CBC decrypt: ");
                                                                        // dump(result, 64);
                                                                        if (0 == myMemcmp((char *)in, (char *)result, plaintextlen))
                                                                        {
                                                                            ffp_msg("SUCCESS:");
#if DBG_MSG
                                                                            ffp_msg("CBC decrypt: \n");
#endif
                                                                            dumpkey(key, keylen);
                                                                            dumpdata(result, plaintextlen);
                                                                            time(&rawtime);
                                                                            timeinfo = localtime(&rawtime);
#if DBG_MSG
                                                                            ffp_msg("End Time: %s\n", asctime(timeinfo));
#endif
                                                                            return (0);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            t2 = clock();
//time(&rawtime);
//timeinfo = localtime(&rawtime);
#if DBG_MSG
                                                            ffp_msg("working itme :: %f second - %0.2f%%\n", (t2 - t1) / (double)CLOCKS_PER_SEC, (100 * donecount / totcount));
                                                            ffp_msg("(%02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X)\n", n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, n12, n13, n14, n15, n16);
#else
                                                            ffp_msg("%0.2f%%\n", (100 * donecount / totcount));
                                                            fflush(stdout);
#endif
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    { // demo mode

        int start0 = 0, start1 = 0, start2 = 0, start3 = 0, start4 = 0, start5 = 0, start6 = 0;
#if DBG_MSG
        ffp_msg("Demo mode decrypt(key len : %d, plain text len : %d, enLevel : %d\n", keylen, plaintextlen, enlevel);
#endif
        int count0, count1 = 0xff, count2 = 0xff, count3 = 0xff, count4 = 0xff, count5 = 0xff, count6 = 0xff;
        if (enlevel == 0)
        {
            start5 = startindex;
            count5 = endindex;

            count0 = count1 = count2 = count3 = count4 = 0;
            totcount = ((endindex - startindex + 1) * 256);
        }
        else if (enlevel == 1)
        {
            start4 = startindex;
            count4 = endindex;
            count5 = 0xf, count6 = 0xf;
            count0 = count1 = count2 = count3 = 0;
            totcount = ((endindex - startindex + 1) * pow(16, 2));
        }
        else if (enlevel == 2)
        {
            start3 = startindex;
            count3 = endindex;
            count4 = 0xf, count5 = 0xf, count6 = 0xf;
            count0 = count1 = count2 = 0;
            totcount = ((endindex - startindex + 1) * pow(16, 3));
        }
        else if (enlevel == 3)
        {
            start2 = startindex;
            count2 = endindex;
            count3 = 0xf, count4 = 0xf, count5 = 0xf, count6 = 0xf;
            count0 = count1 = 0;
            totcount = ((endindex - startindex + 1) * pow(16, 4));
        }
        else if (enlevel == 4)
        {
            start1 = startindex;
            count1 = endindex;
            count2 = 0xf, count3 = 0xf, count4 = 0xf, count5 = 0xf, count6 = 0xf;
            count0 = 0;
            totcount = ((endindex - startindex + 1) * pow(16, 5));
        }
        else if (enlevel == 5)
        {
            start0 = startindex;
            count0 = endindex;
            count1 = 0xf, count2 = 0xf, count3 = 0xf, count4 = 0xf, count5 = 0xf, count6 = 0xf;
            totcount = ((endindex - startindex + 1) * pow(16, 6));
        }
        for (n0 = start0; n0 <= count0; n0++)
        {
            for (n1 = start1; n1 <= count1; n1++)
            {
                for (n2 = start2; n2 <= count2; n2++)
                {
                    for (n3 = start3; n3 <= count3; n3++)
                    {
                        for (n4 = start4; n4 <= count4; n4++)
                        {
                            t1 = clock();
                            for (n5 = start5; n5 <= count5; n5++)
                            {
                                for (n6 = start6; n6 <= count6; n6++)
                                {
                                    if (enlevel == 0)
                                    {
                                        key[keyindex + 14] = n5;
                                        key[keyindex + 15] = n6;
                                    }
                                    else if (enlevel == 1)
                                    {
                                        key[keyindex + 13] = n4;
                                        key[keyindex + 14] = (key[keyindex + 14] & 0xf0) | (n5 & 0x0f);
                                        key[keyindex + 15] = (key[keyindex + 15] & 0xf0) | (n6 & 0x0f);
                                    }
                                    else if (enlevel == 2)
                                    {
                                        key[keyindex + 12] = n3;
                                        key[keyindex + 13] = (key[keyindex + 13] & 0xf0) | (n4 & 0x0f);
                                        key[keyindex + 14] = (key[keyindex + 14] & 0xf0) | (n5 & 0x0f);
                                        key[keyindex + 15] = (key[keyindex + 15] & 0xf0) | (n6 & 0x0f);
                                    }
                                    else if (enlevel == 3)
                                    {
                                        key[keyindex + 11] = n2;
                                        key[keyindex + 12] = (key[keyindex + 12] & 0xf0) | (n3 & 0x0f);
                                        key[keyindex + 13] = (key[keyindex + 13] & 0xf0) | (n4 & 0x0f);
                                        key[keyindex + 14] = (key[keyindex + 14] & 0xf0) | (n5 & 0x0f);
                                        key[keyindex + 15] = (key[keyindex + 15] & 0xf0) | (n6 & 0x0f);
                                    }
                                    else if (enlevel == 4)
                                    {
                                        key[keyindex + 10] = n1;
                                        key[keyindex + 11] = (key[keyindex + 11] & 0xf0) | (n2 & 0x0f);
                                        key[keyindex + 12] = (key[keyindex + 12] & 0xf0) | (n3 & 0x0f);
                                        key[keyindex + 13] = (key[keyindex + 13] & 0xf0) | (n4 & 0x0f);
                                        key[keyindex + 14] = (key[keyindex + 14] & 0xf0) | (n5 & 0x0f);
                                        key[keyindex + 15] = (key[keyindex + 15] & 0xf0) | (n6 & 0x0f);
                                    }
                                    else if (enlevel == 5)
                                    {
                                        key[9] = n0;
                                        key[10] = (key[keyindex + 10] & 0xf0) | (n1 & 0x0f);
                                        key[11] = (key[keyindex + 11] & 0xf0) | (n2 & 0x0f);
                                        key[12] = (key[keyindex + 12] & 0xf0) | (n3 & 0x0f);
                                        key[13] = (key[keyindex + 13] & 0xf0) | (n4 & 0x0f);
                                        key[14] = (key[keyindex + 14] & 0xf0) | (n5 & 0x0f);
                                        key[15] = (key[keyindex + 15] & 0xf0) | (n6 & 0x0f);
                                    }

                                    AES_ctx_set_iv(&ctx, iv);
                                    AES_init_ctx(&ctx, key);
                                    AES_CBC_decrypt_bufferEx(&ctx, out, result, plaintextlen);
                                    donecount++;

                                    // dump(result, 64);
                                    if (0 == myMemcmp((char *)in, (char *)result, plaintextlen))
                                    {
                                        ffp_msg("SUCCESS:");
#if DBG_MSG
                                        ffp_msg("CBC decrypt: \n");
#endif
                                        dumpkey(key, keylen);
                                        dumpdata(result, plaintextlen);
                                        time(&rawtime);
                                        timeinfo = localtime(&rawtime);
#if DBG_MSG
                                        ffp_msg("End Time: %s\n", asctime(timeinfo));
#endif
                                        return (0);
                                    }
                                }
                            }
                        }
                        t2 = clock();
                        time(&rawtime);
                        timeinfo = localtime(&rawtime);
#if DBG_MSG
                        ffp_msg("working itme :: %f second - %0.2f%%\n", (t2 - t1) / (double)CLOCKS_PER_SEC, (100 * donecount / totcount));
                        ffp_msg("(%02X, %02X, %02X, %02X)\n", n1, n2, n3, n4);
#else
                        //ffp_msg("%f, %f, %0.2f%%\n", donecount, totcount, (100 * donecount / totcount));
                        ffp_msg("%0.2f%%\n", (100 * donecount / totcount));
#endif
                    }
                }
            }
        }
    }
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    ffp_msg("\nFAILURE!\n");
#if DBG_MSG
    ffp_msg("End time and date: %s", asctime(timeinfo));
#endif
    return (1);
}


//암호화 테스트 함수
static int test_encrypt_cbc(char * argv[])
{

    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    FILE *fp, *dptr, *iptr;
  // char sdata[Max_data_len];
  // int8_t edata[Max_data_len];

    size_t filesize = 0;
    int keylen = 16;
    int plaintextlen = 188 * 16;
    int enlevel = atoi((const char *)argv[2]);

    if (enlevel > 5)
    {
        ffp_msg("info : if enlevel more then 5, it is not effectve to demo system(meaning not demo)(%d) \n", enlevel);
        return 0;
    }


  //  #ifdef _WIN32 || _WIN64 // defined(__Winows__) || defined(__linux__)

#if DBG_MSG
     ffp_msg("start opening file\n");
#endif
    char strBuffer[_MAX_PATH] = {
        0,
    };
    char *pstrBuffer = NULL;

    pstrBuffer = getcwd(strBuffer, _MAX_PATH);
    ffp_msg(pstrBuffer);
    ffp_msg("\n");

    int index = 0;
    char project_id[100];
    char dataname[_MAX_PATH];
    char infoname[_MAX_PATH];
    char OS_TYPE[10];
    int rlen = 0;
#ifdef _WIN32 //|| _WIN64
    sprintf(OS_TYPE, "WIN");
#elif __APPLE__
    sprintf(OS_TYPE, "MAC");
#elif __linux__
    sprintf(OS_TYPE, "LINUX");
#elif __unix__ // all unices not caught above
    sprintf(OS_TYPE, "UNIX");
#elif defined(_POSIX_VERSION)
    sprintf(OS_TYPE, "POSIX");
#else
#   error "Unknown compiler"
    sprintf(OS_TYPE, "NONE");
#endif

    if ((fp = fopen(argv[3], "rb")) == NULL)
    {
        ffp_msg("Error! opening file");
        // Program exits if the file pointer returns NULL.
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    printf("os type : %s, %d\n", OS_TYPE, filesize);
    sprintf(project_id, "%s", argv[4]);

    //while(filesize > 0){

    srand(time(NULL));
    while(!feof(fp)) {

        memset(in, 0, plaintextlen);
        rlen = fread(in, 1, plaintextlen,  fp);
        //dump(in, plaintextlen);
        printf("read info : %d - %d - %d\n", plaintextlen, rlen, index);
        if (rlen <= 0)
        {
            break;
        }
        if (rlen < plaintextlen)
        {
            rlen = (rlen + (keylen - 1)) / keylen * keylen;
        }

        sprintf(dataname, "D_%s_%s_%06d_00_ddata.dat", OS_TYPE, project_id, index);
        sprintf(infoname, "I_%s_%s_%06d_00_idata.dat", OS_TYPE, project_id, index);
        index++;

        printf("file info : %s - %s\n", dataname, infoname);
        dptr = fopen(dataname, "wb");
        if (dptr == NULL)
        {
            ffp_msg("open data file Error!");
            exit(1);
        }

        iptr = fopen(infoname, "wb");
        if (iptr == NULL)
        {
            ffp_msg("open info file Error!");
            exit(1);
        }

        if (strncmp(argv[1], "demo", 4) == 0)
        {
            fprintf(iptr, "00%04X%04X%02X", keylen, rlen, enlevel);
        }
        else
        {
            fprintf(iptr, "11%04X%04X%02X", keylen, rlen, enlevel);
        }

        //암호화 키 공개키 고정값
        int i = 0;

        //fprintf(iptr, "IV : \n");
        for (i = 0; i < keylen; i++)
        {
            //write  iv
            iv[i] = rand() & 0xFF;
            fprintf(iptr, "%02X", iv[i]);

        }
        if (strncmp(argv[1], "demo", 4) == 0)
        {
            ffp_msg("Gen info of demo mode : keylen(%d), plaintextlen(%d), enlevel(%d)\n", keylen, rlen, enlevel);
            //fprintf(iptr, "\n KEY : \n");
           // printf("\n KEY : \n");
            for (i = 0; i < keylen; i++)
            {
                key[i] = rand() & 0xFF;
               // printf("IV, %X\n", key[i]);
                //write  key
                if (enlevel == 0)
                {
                    if (i >= keylen - 2)
                    {
                        fprintf(iptr, "%02X", 0x00);
                    }
                    else
                    {
                        fprintf(iptr, "%02X", key[i]);
                    }
                }
                else if (enlevel == 1)
                {
                    if (i >= keylen - 3)
                    {
                        if (i >= (keylen - 2))
                        {
                            fprintf(iptr, "%02X", (key[i] & 0xf0));
                        }
                        else
                        {
                            fprintf(iptr, "%02X", 0x00);
                        }
                    }
                    else
                    {
                        fprintf(iptr, "%02X", key[i]);
                    }
                }
                else if (enlevel == 2)
                {
                    // ffp_msg("level (%d) : %d, %d \n ", enlevel, i, keylen);

                    if (i >= keylen - 4)
                    {
                        if (i >= (keylen - 3))
                        {
                            fprintf(iptr, "%02X", (key[i] & 0xf0));
                        }
                        else
                        {
                            fprintf(iptr, "%02X", 0x00);
                        }
                    }
                    else
                    {
                        fprintf(iptr, "%02X", key[i]);
                    }
                }
                else if (enlevel == 3)
                {
                    if (i >= keylen - 5)
                    {
                        if (i >= (keylen - 4))
                        {
                            fprintf(iptr, "%02X", (key[i] & 0xf0));
                        }
                        else
                        {
                            fprintf(iptr, "%02X", 0x00);
                        }
                    }
                    else
                    {
                        fprintf(iptr, "%02X", key[i]);
                    }
                }
                else if (enlevel == 4)
                {
                    if (i >= keylen - 6)
                    {
                        if (i >= (keylen - 5))
                        {
                            fprintf(iptr, "%02X", (key[i] & 0xf0));
                        }
                        else
                        {
                            fprintf(iptr, "%02X", 0x00);
                        }
                    }
                    else
                    {
                        fprintf(iptr, "%02X", key[i]);
                    }
                }
                else if (enlevel == 5)
                {
                    if (i >= keylen - 7)
                    {
                        if (i >= (keylen - 6))
                        {
                            fprintf(iptr, "%02X", (key[i] & 0xf0));
                        }
                        else
                        {
                            fprintf(iptr, "%02X", 0x00);
                        }
                    }
                    else
                    {
                        fprintf(iptr, "%02X", key[i]);
                    }
                }
                else
                {
                    fprintf(iptr, "%02X", key[i]);
                }
            }

            ffp_msg("New Key Gen : \n");
            dump(key, keylen);
           // fprintf(sptr, "\n PlainText : \n");
            // for (i = 0; i < plaintextlen; i++)
            // {
            //     in[i] = rand() & 0xFF;
            //     //write  plain Text
            //     fprintf(iptr, "%02X", in[i]);
            //     //fprintf(sptr, "%02X", in[i]);
            // }

           // ffp_msg("New Plain Text : ");
           // dump(in, plaintextlen);
        }
        else
        {
            ffp_msg("\nGen info of release mode : keylen(%d), plaintextlen(%d), enlevel(%d)\n\n", keylen, rlen, enlevel);
           // fprintf(sptr, "\n KEY : \n");
            for (i = 0; i < keylen; i++)
            {
                key[i] = rand() & 0xFF;
                //write  key
                fprintf(iptr, "%02X", 0x00);
                //fprintf(sptr, "%02X", key[i]);
            }
            ffp_msg("New Key Gen : ");
            dump(key, keylen);

            //fprintf(sptr, "\n PlainText : \n");

            // for (i = 0; i < plaintextlen; i++)
            // {
            //     in[i] = rand() & 0xFF;
            //     //write  plain Text
            //     fprintf(iptr, "%02X", in[i]);
            //     //fprintf(sptr, "%02X", in[i]);
            // }
            // ffp_msg("New Plain Text : ");
           // dump(in, plaintextlen);
        }

        //aes 구조체
        struct AES_ctx ctx;

        //초기화 벡터값과 공개키로 RoundKey 생성 - 이곳에서 시간 소모가 가장 큼
        AES_init_ctx_iv(&ctx, key, iv);

        /*
    실제 암호화 함수
    aes 구조체 포인터, 원본 데이터, 결과를 저장할 변수, 데이터 길이
    암호화된 데이터는 inConv 변수를 통해 받을 수 있다. 
    */
        //ffp_msg("CBC source in 1: ");
        //dump(in, plaintextlen);
        AES_CBC_encrypt_bufferEx(&ctx, in, inConv, plaintextlen);
       // fprintf(sptr, "\n CyperText : \n");
        // for (i = 0; i < plaintextlen; i++)
        // {
        //     //write  encrypt data
        //     //fprintf(iptr, "%02X", inConv[i]);
        //     fprintf(dptr, "%02X", inConv[i]);
           
        // }
         fwrite(inConv, 1, plaintextlen, dptr);
        // ffp_msg("CBC source in 2: ");
        // dump(in, 64);

        ffp_msg("CBC encrypt: ");
        //dump(inConv, plaintextlen);
        //미리 정상적으로 암호화해둔 데이터(out)와 현재 암호화한 데이터(inConv)가 동일하다면 성공
        // if (0 == myMemcmp((char*) out, (char*)inConv, 64)) {
        //     ffp_msg("SUCCESS!\n");
        //     return(0);
        // } else {
        //     ffp_msg("FAILURE!\n");
        //     return(1);
        // }
        fclose(dptr);
        fclose(iptr);
    }
     fclose(fp);
  //   ShellExecute(NULL, "open", "notepad", path, NULL, SW_SHOW);

}

//#define TEST  0 
int main(int argc, char * argv[])
{
    time_t rawtime, start, end;
    clock_t t1, t2;
    double timer1;
    char argvtemp[3][MAX_PATH];
    int exit;    

    time(&start);



  #if 0
    if (1) //decrypt mode
    {

        if (argc == 1)
        {
         
            sprintf(argvtemp[0], "%s", argv[0] );           
            sprintf(argvtemp[1], "%d", START);           
            sprintf(argvtemp[2], "%d", END);             
            argc = 3;
            //ffp_msg("agrc = %d, %s, %s, %s\n", argc, argvtemp[0], argvtemp[1], argvtemp[2]);
        }
        else if (argc == 3)
        {
            strcpy(argvtemp[0], argv[0] );
            strcpy(argvtemp[1], argv[1] );
            strcpy(argvtemp[2], argv[2] );
        }
        else
        {
            ffp_msg("Error3");
            ffp_msg("Error! it need 2 argc(%d), argv[0] = %s, argv[1] = %s, argv[2] = %s\n", argc, argv[0], argv[1], argv[2]);
            return 0;
        }
        // ffp_msg("info %d, %d", atoi(argvtemp[1]), atoi(argvtemp[2]));
        if ((atoi(argvtemp[1]) < 0) && (atoi(argvtemp[1]) > 255))
        {
            ffp_msg("Error info : Index(%s) must be between 0 ~ 255\n", argvtemp[1]);
            return 0;
        }
        if ((atoi(argvtemp[2]) < 1) && (atoi(argvtemp[2]) > 255))
        {
            ffp_msg("Error info : total count(%s) must be between 1 ~ 255\n", argvtemp[2]);
            return 0;
        }
        #if DBG_MSG 
        ffp_msg("\nStart decrypt_CBC start Task_Index(%s) and total count(%s)\n", argvtemp[1], argvtemp[2]);
        #endif
        exit = test_decrypt_cbc(argvtemp);
    }
  
    #endif 
    {

        if (argc != 5)
        {
            ffp_msg("Error! it need 4 argc(%d), execute mode level datapath project_id\n");
            return 0;
        }
        ffp_msg("Start Encrypt_CBC Mode(%s, %s, %s, %s)\n", argv[1], argv[2], argv[3], argv[4] );
        exit = test_encrypt_cbc(argv);
    }
    time(&end);
    timer1 = difftime(end, start);
    ffp_msg("%0.2f second\n", timer1);
    return exit;
}