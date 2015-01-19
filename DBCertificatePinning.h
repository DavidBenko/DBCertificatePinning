//
//  DBCertificatePinning.h
//  CertPinningTest
//
//  Created by David Benko on 12/19/14.
//  Copyright (c) 2014 David Benko. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, DBCertifcatePinningAllowPolicy) {
    DBCertifcatePinningAllowPolicyOnlyPinned,
    DBCertifcatePinningAllowPolicyAll
};

typedef NS_ENUM(NSInteger, DBCertifcatePinningPinType) {
    DBCertifcatePinningPinTypePublicKey,
    DBCertifcatePinningPinTypeCertificate
};

@interface DBCertificatePinning : NSObject

+ (void)pinDomain:(NSString *)domain toCertificateAtPath:(NSString *)certificatePath;
+ (void)pinDomain:(NSString *)domain toCertificate:(NSData *)certificate;

+ (NSURLConnection *)executePinnedConnectionForRequest:(NSURLRequest *)request;

+ (void)setPinType:(DBCertifcatePinningPinType)pinningType;
+ (void)setAllowPolicy:(DBCertifcatePinningAllowPolicy)pinningAllowPolicy;
@end
