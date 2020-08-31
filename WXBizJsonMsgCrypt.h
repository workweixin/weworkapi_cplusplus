
#pragma once

#include <string>
#include <stdint.h>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace Tencent {

static const unsigned int kAesKeySize = 32;
static const unsigned int kAesIVSize = 16;
static const unsigned int kEncodingKeySize = 43;
static const unsigned int kRandEncryptStrLen = 16;
static const unsigned int kMsgLen = 4;
static const unsigned int kMaxBase64Size = 1000000000;
enum  WXBizJsonMsgCryptErrorCode
{
    WXBizMsgCrypt_OK = 0,
    WXBizMsgCrypt_ValidateSignature_Error = -40001,
    WXBizMsgCrypt_ParseJson_Error = -40002,
    WXBizMsgCrypt_ComputeSignature_Error = -40003,
    WXBizMsgCrypt_IllegalAesKey = -40004,
    WXBizMsgCrypt_ValidateCorpid_Error = -40005,
    WXBizMsgCrypt_EncryptAES_Error = -40006,
    WXBizMsgCrypt_DecryptAES_Error = -40007,
    WXBizMsgCrypt_IllegalBuffer = -40008,
    WXBizMsgCrypt_EncodeBase64_Error = -40009,
    WXBizMsgCrypt_DecodeBase64_Error = -40010,
    WXBizMsgCrypt_GenReturnJson_Error = -40011,
};

class WXBizJsonMsgCrypt
{
public:
    //���캯��
    // @param sToken: ��ҵ΢�ź�̨�����������õ�Token
    // @param sEncodingAESKey: ��ҵ΢�ź�̨�����������õ�EncodingAESKey
    // @param sReceiveId: ��ͬ�������岻ͬ������ĵ�
    WXBizJsonMsgCrypt(const std::string &sToken, 
                    const std::string &sEncodingAESKey, 
                    const std::string &sReceiveId)
                    :m_sToken(sToken), m_sEncodingAESKey(sEncodingAESKey),m_sReceiveId(sReceiveId)
                    {   }
	//��֤URL
	// @param sMsgSignature: ǩ��������ӦURL������msg_signature
	// @param sTimeStamp: ʱ�������ӦURL������timestamp
	// @param sNonce: ���������ӦURL������nonce
	// @param sEchoStr: ���������ӦURL������echostr
	// @param sReplyEchoStr: ����֮���echostr����return����0ʱ��Ч
	// @return���ɹ�0��ʧ�ܷ��ض�Ӧ�Ĵ�����
	int VerifyURL(const std::string& sMsgSignature,
					const std::string& sTimeStamp,
					const std::string& sNonce,
					const std::string& sEchoStr,
					std::string& sReplyEchoStr);
    
    
    // ������Ϣ����ʵ�ԣ����һ�ȡ���ܺ������
    // @param sMsgSignature: ǩ��������ӦURL������msg_signature
    // @param sTimeStamp: ʱ�������ӦURL������timestamp
    // @param sNonce: ���������ӦURL������nonce
    // @param sPostData: ���ģ���ӦPOST���������
    // @param sMsg: ���ܺ��ԭ�ģ���return����0ʱ��Ч
    // @return: �ɹ�0��ʧ�ܷ��ض�Ӧ�Ĵ�����
    int DecryptMsg(const std::string &sMsgSignature,
                    const std::string &sTimeStamp,
                    const std::string &sNonce,
                    const std::string &sPostData,
                    std::string &sMsg);
            
            
    //����ҵ΢�Żظ��û�����Ϣ���ܴ��
    // @param sReplyMsg:��ҵ΢�Ŵ��ظ��û�����Ϣ��json��ʽ���ַ���
    // @param sTimeStamp: ʱ����������Լ����ɣ�Ҳ������URL������timestamp
    // @param sNonce: ������������Լ����ɣ�Ҳ������URL������nonce
    // @param sEncryptMsg: ���ܺ�Ŀ���ֱ�ӻظ��û������ģ�����msg_signature, timestamp, nonce, encrypt��json��ʽ���ַ���,
    //                      ��return����0ʱ��Ч
    // return���ɹ�0��ʧ�ܷ��ض�Ӧ�Ĵ�����
    int EncryptMsg(const std::string &sReplyMsg,
                    const std::string &sTimeStamp,
                    const std::string &sNonce,
                    std::string &sEncryptMsg);
					
	int GetJsonField(const std::string & sPostData, const std::string & sField, std::string &sEncryptMsg);
    int GetJsonField(const std::string & sPostData, const std::string & sField, uint32_t & uValue);
    int GetJsonField(const std::string & sPostData, const std::string & sField, uint64_t & uValue);
private:
    std::string m_sToken;
    std::string m_sEncodingAESKey;
    std::string m_sReceiveId;

private:
    // AES CBC
    int AES_CBCEncrypt( const char * sSource, const uint32_t iSize,
            const char * sKey, unsigned int iKeySize, std::string * poResult );
    
    int AES_CBCEncrypt( const std::string & objSource,
            const std::string & objKey, std::string * poResult );
    
    int AES_CBCDecrypt( const char * sSource, const uint32_t iSize,
            const char * sKey, uint32_t iKeySize, std::string * poResult );
    
    int AES_CBCDecrypt( const std::string & objSource,
            const std::string & objKey, std::string * poResult );
    
    //base64
    int EncodeBase64(const std::string sSrc, std::string & sTarget);
    
    int DecodeBase64(const std::string sSrc, std::string & sTarget);
    
    //genkey
    int GenAesKeyFromEncodingKey( const std::string & sEncodingKey, std::string & sAesKey);
    
    //signature
    int ComputeSignature(const std::string sToken, const std::string sTimeStamp, const std::string & sNonce,
        const std::string & sMessage, std::string & sSignature);
    
    int ValidateSignature(const std::string &sMsgSignature, const std::string &sTimeStamp, 
        const std::string &sNonce, const std::string & sEncryptMsg);  

    //get , set data
    void GenRandStr(std::string & sRandStr, uint32_t len);

    void GenNeedEncryptData(const std::string &sReplyMsg,std::string & sNeedEncrypt );

    int SetOneFieldToJson(rapidjson::Document & Doc, const char * pcField, const char * pcValue);

    int GenReturnJson(const std::string & sEncryptMsg, const std::string & sSignature, const std::string & sTimeStamp, 
        const std::string & sNonce, std::string & sResult);


};

}
