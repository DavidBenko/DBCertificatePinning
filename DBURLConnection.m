//
//  DBURLConnection.m
//  CertPinningTest
//
//  Created by David Benko on 1/19/15.
//  Copyright (c) 2015 David Benko. All rights reserved.
//

#import "DBURLConnection.h"

@implementation DBURLConnection
- (instancetype)initWithRequest:(NSURLRequest *)request delegate:(id)delegate{
    self = [super initWithRequest:request delegate:delegate];
    if (self) {
        self.requestURL = request.URL;
    }
    return self;
}
@end
