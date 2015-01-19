//
//  DBCertificatePinning.m
//  CertPinningTest
//
//  Created by David Benko on 12/19/14.
//  Copyright (c) 2014 David Benko. All rights reserved.
//

#import "DBCertificatePinning.h"
#import "DBURLConnection.h"

static NSMutableDictionary *pinnedDomains = nil;
static DBCertificatePinning *connectionDelegate = nil;
static DBCertifcatePinningAllowPolicy allowPolicy = DBCertifcatePinningAllowPolicyOnlyPinned;
static DBCertifcatePinningPinType pinType = DBCertifcatePinningPinTypePublicKey;

@interface DBCertificatePinning () <NSURLConnectionDelegate>
@end

@implementation DBCertificatePinning

+ (void)initialize{
    if (!pinnedDomains){
        pinnedDomains = [[NSMutableDictionary alloc]init];
    }
    
    if (!connectionDelegate) {
        connectionDelegate = [[DBCertificatePinning alloc]init];
    }
}

+ (void)pinDomain:(NSString *)domain toCertificateAtPath:(NSString *)certificatePath{
    
    if (certificatePath == nil) {
        NSLog(@"Can not find certificat at path: %@", certificatePath);
        return;
    }
    
    NSData *certificateFileContent = [NSData dataWithContentsOfFile:certificatePath];
    return [self pinDomain:domain toCertificate:certificateFileContent];
}

+ (void)pinDomain:(NSString *)domain toCertificate:(NSData *)certificate{
    [pinnedDomains setObject:certificate forKey:domain];
}

+ (NSURLConnection *)executePinnedConnectionForRequest:(NSURLRequest *)request{
    DBURLConnection* connection = [[DBURLConnection alloc] initWithRequest:request delegate:connectionDelegate];
    return connection;
}

+ (void)setPinType:(DBCertifcatePinningPinType)pinningType{
    pinType = pinningType;
}

+ (void)setAllowPolicy:(DBCertifcatePinningAllowPolicy)pinningAllowPolicy{
    allowPolicy = pinningAllowPolicy;
}

-(BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:
(NSURLProtectionSpace*)space{
    return [[space authenticationMethod] isEqualToString: NSURLAuthenticationMethodServerTrust];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:
(NSURLAuthenticationChallenge *)challenge{
    
    /*
     * Pinning Code is a modified version of code found at:
     * https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#iOS
     */
    
    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString: NSURLAuthenticationMethodServerTrust])
    {
        do
        {
            SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
            if(!serverTrust){
                break; /* failed */
            }
            
            OSStatus status = SecTrustEvaluate(serverTrust, NULL);
            if(!(errSecSuccess == status)){
                break; /* failed */
            }
            
            SecCertificateRef serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
            if(!serverCertificate){
                break; /* failed */
            }
            
            CFDataRef serverCertificateData = SecCertificateCopyData(serverCertificate);
            if(!serverCertificateData){
                break; /* failed */
            }
            
            SecKeyRef serverPublicKey = SecTrustCopyPublicKey(serverTrust);
            
            const UInt8* const data = CFDataGetBytePtr(serverCertificateData);
            const CFIndex size = CFDataGetLength(serverCertificateData);
            NSData* serverCertData = [NSData dataWithBytes:data length:(NSUInteger)size];
            
            NSString *domain = [[((DBURLConnection *)connection) requestURL] host];
            NSData* pinningCertData = [pinnedDomains objectForKey:domain];
            
            if (!pinningCertData) {
                NSLog(@"Pinning cert not found for domain: %@",domain);
                if (allowPolicy == DBCertifcatePinningAllowPolicyAll) {
                    NSLog(@"Unpinned SSL Connection Allowed!");
                    return [[challenge sender] useCredential: [NSURLCredential credentialForTrust: serverTrust]
                                  forAuthenticationChallenge: challenge];
                }
                
                break;
            }
            
            
            //verify pinning cert
            SecCertificateRef pinningCertificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)pinningCertData);
            
            SecPolicyRef secPolicy = SecPolicyCreateBasicX509();
            SecTrustRef pinningTrust;
            OSStatus statusTrust = SecTrustCreateWithCertificates(pinningCertificate, secPolicy, &pinningTrust);
            SecTrustResultType pinningTrustResultType;
            OSStatus statusTrustEval =  SecTrustEvaluate(pinningTrust, &pinningTrustResultType);
            
            if (!(errSecSuccess == statusTrust)) {
                break;
            }
            
            if (!(errSecSuccess == statusTrustEval)) {
                break;
            }
            
            SecKeyRef pinningPublicKey = SecTrustCopyPublicKey(pinningTrust);
            
            // Certificate Check
            if (pinType == DBCertifcatePinningPinTypeCertificate &&
                (![serverCertData isEqualToData:pinningCertData])) {
                NSLog(@"Certificate pin FAILED for %@", domain);
                break;
            }
            
            // Public Key Check
            if (pinType == DBCertifcatePinningPinTypePublicKey) {
                NSData * serverKeyData = [self getPublicKeyBitsFromKey:serverPublicKey];
                NSData * pinningKeyData = [self getPublicKeyBitsFromKey:pinningPublicKey];
                
                if (![serverKeyData isEqualToData:pinningKeyData]) {
                    NSLog(@"Public Key pin FAILED for %@", domain);
                    break;
                }
            }
            
            NSLog(@"Connection to %@ successfully pinned and validated", domain);
            return [[challenge sender] useCredential: [NSURLCredential credentialForTrust: serverTrust]
                          forAuthenticationChallenge: challenge];
        } while(0);
        
        return [[challenge sender] cancelAuthenticationChallenge: challenge];
    }
}

- (NSData *)getPublicKeyBitsFromKey:(SecKeyRef)givenKey {
    
    static const uint8_t publicKeyIdentifier[] = "com.your.company.publickey";
    NSData *publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
    
    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Temporarily add key to the Keychain, return as data:
    NSMutableDictionary * attributes = [queryPublicKey mutableCopy];
    [attributes setObject:(__bridge id)givenKey forKey:(__bridge id)kSecValueRef];
    [attributes setObject:@YES forKey:(__bridge id)kSecReturnData];
    CFTypeRef result;
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) attributes, &result);
    if (sanityCheck == errSecSuccess) {
        publicKeyBits = CFBridgingRelease(result);
        
        // Remove from Keychain again:
        (void)SecItemDelete((__bridge CFDictionaryRef) queryPublicKey);
    }
    
    return publicKeyBits;
}
@end
