#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/base64.h>

int main()
{
    
    int ret=0;
    
    // random data generator
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    
    // randomness with seed
    mbedtls_ctr_drbg_context ctr_drbg;
    char *personalization = "My RSA demo";
    mbedtls_ctr_drbg_init( &ctr_drbg );
    
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
                                (const unsigned char *) personalization,
                                strlen( personalization ) );
    if( ret != 0 )
    {
        // ERROR HANDLING CODE FOR YOUR APP
    }
    mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg,
                                               MBEDTLS_CTR_DRBG_PR_ON );
    ////////////////////////////////////////////////////////////////////////
    
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );
    
    unsigned char to_encrypt[]="Yongpeng.Zhu";
    unsigned char to_decrypt[MBEDTLS_MPI_MAX_SIZE];
    const unsigned char pub_key[]=
    "-----BEGIN PUBLIC KEY-----\r\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRwBcxeI0LTFJrBevaMSV2B5mj\r\n"
    "WF51b/VAmAb76L1IVQJx1JjCSI25G3P5omdPzS7Mbe2rlyHwOWjS3A6V6YiEYtwh\r\n"
    "JcAM7Z+gbwzCbjPSd/N+ONrmCwJcmj5xQky1prvtZhfxRRdd89fHm8yZ9JKO/kpX\r\n"
    "R/v2BSDl+q89aQmxmwIDAQAB\r\n"
    "-----END PUBLIC KEY-----\r\n";
    
    const unsigned char prv_pwd[]="password";
    const unsigned char prv_key[]=
    "-----BEGIN RSA PRIVATE KEY-----\r\n"
    "MIICXQIBAAKBgQCRwBcxeI0LTFJrBevaMSV2B5mjWF51b/VAmAb76L1IVQJx1JjC\r\n"
    "SI25G3P5omdPzS7Mbe2rlyHwOWjS3A6V6YiEYtwhJcAM7Z+gbwzCbjPSd/N+ONrm\r\n"
    "CwJcmj5xQky1prvtZhfxRRdd89fHm8yZ9JKO/kpXR/v2BSDl+q89aQmxmwIDAQAB\r\n"
    "AoGAIEaqnDD3AwZ+xeaEyUfS5OVf95VNLbKCXDCOc2Ch8g+pP+31eii5AcH7l8+I\r\n"
    "E1r7vxek5zfLszfzZ6aFsFsL+PYOzZtpo74pDzQNJjRZ8bjWfud+GmBP/eWRM8fp\r\n"
    "/Yi42q239QZhkyn69p5g8GxREfd3ShEYderpb5wWFPpPqLECQQDp9k0uyE8Uj0xY\r\n"
    "qEIfYycj6EBGGF10XpGYZghgdjsoCIw2DJWaN2xMeVv2tCNxag2gVq2EuAQLs851\r\n"
    "9jWVcSIZAkEAn3qsv6V4COw/43GjVK+3twg67qHVHketNFhXgV9IDSq89ISZEGn6\r\n"
    "3o9k+KAvA/hBtvkfN2lJmZ7cZlXp9Mgv0wJBANwUJGZtZnYgleCP5iNAUgEk59EH\r\n"
    "+mEM1EhXMmoKzXrLD5mIHPIEUItfXXKj4PM+n7LD1lWSA7w+V2f/QkhhM4ECQFld\r\n"
    "cLfjjSPS3uogn5mw7Y2O+xcFcFsLZy9R4ZcJQWK/dCrAstTTzlQwnjAD8tSSpKBX\r\n"
    "cPqn8So4LuDZe8RC+SkCQQClVaBFsCe4JaOw8QuvhnbrwPuxAq7IovmpfxZi8YGZ\r\n"
    "98zt/M9uk/NBvvqzJn3MaPRMSUeWyic4b8/hZUhXUW3A\r\n"
    "-----END RSA PRIVATE KEY-----\r\n";
    
    if( ( ret = mbedtls_pk_parse_public_key( &pk, pub_key, sizeof(pub_key) ) ) != 0 )
    {
        printf( " failed\n ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
        return -1;
    }
    
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;
    
    if( ( ret = mbedtls_pk_encrypt( &pk, to_encrypt, sizeof(to_encrypt),
                                   buf, &olen, sizeof(buf),
                                   mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
        return -1;
    }
    
    printf( "\nGenerating the encrypted value\n" );
    fflush( stdout );
    
    printf("buf hex value: \n");
    for(int idx=0; idx<strlen(buf); printf("%02x", buf[idx++]));
    printf("\n");
    
    printf("buf: %s \n",buf);
    printf("buf length: %d \n",olen);
    
    // ==========================================================
    // ====================== 开始 Base64编码 =====================
    // ==========================================================
    unsigned char results[MBEDTLS_MPI_MAX_SIZE];
    memset(results, 0, MBEDTLS_MPI_MAX_SIZE);
    // base64 encode 后字节数
    size_t olen1 = 0;
    int ret1 = mbedtls_base64_encode((unsigned char*)results, sizeof(results),&olen1,buf, olen);
    printf("Base64 Encode 是否成功: %d \n",ret1);
    printf("Base64 Encode 后结果: %s \n",results);
    // ==========================================================
    // ====================== 结束 Base64编码 =====================
    // ==========================================================
    
    
    // ==========================================================
    // ====================== 开始Base64解码 ======================
    // ==========================================================
    unsigned char results1[MBEDTLS_MPI_MAX_SIZE];
    memset(results1, 0, MBEDTLS_MPI_MAX_SIZE);
    // base64 decode 后字节数
    size_t olen2 = 0;
    int ret2 = mbedtls_base64_decode((unsigned char*)results1, sizeof(results1), &olen2, results, olen1);
    printf("Base64 Decode 是否成功: %d \n",ret2);
    printf("Base64 Decode 后结果: %s \n",results1);
    printf("Base64 Decode Length: %d \n",olen2);
    // ==========================================================
    // ====================== 结束Base64解码 ======================
    // ==========================================================
    
    
    mbedtls_pk_context pk1;
    mbedtls_pk_init(&pk1);
    if( ( ret = mbedtls_pk_parse_key( &pk1, prv_key, sizeof(prv_key), prv_pwd, strlen(prv_pwd) ) ) != 0 )
    {
        printf( " failed\n ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
        return -1;
    }
    
    unsigned char result[MBEDTLS_MPI_MAX_SIZE];
    printf( "\nGenerating the decrypted value" );
    fflush( stdout );
    
    size_t olen3 = 0;
    //    if( ( ret = mbedtls_pk_decrypt( &pk1, buf, olen, result, &olen, sizeof(result),
    if( ( ret = mbedtls_pk_decrypt( &pk1, results1, olen2, result, &olen3, sizeof(result),
                                   mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n! mbedtls_pk_decrypt returned -0x%04x\n", -ret );
        return -1;
    }
    else
    {
        fflush( stdout );
        printf("\n\n%s----------------\n\n", result);
        printf("RSA Decode Length: %d \n",olen3);
    }
    
    return 0;
}
