//
//  DBURLConnection.h
//  CertPinningTest
//
//  Created by David Benko on 1/19/15.
//  Copyright (c) 2015 David Benko. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DBURLConnection : NSURLConnection
@property (nonatomic, strong) NSURL *requestURL;
@end
