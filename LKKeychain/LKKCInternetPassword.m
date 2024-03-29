//
//  LKKCInternetPassword.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above
//    copyright notice, this list of conditions and the following
//    disclaimer in the documentation and/or other materials provided
//    with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//  
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
//  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL KÁROLY LŐRENTEY BE LIABLE FOR ANY
//  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
//  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 

#import "LKKCInternetPassword.h"
#import "LKKCKeychainItem+Subclasses.h"

#pragma mark - Protocols

typedef struct ProtocolDesc {
	const CFTypeRef *sprotocol;
    LKKCProtocol protocol;
    CFStringRef scheme;
} ProtocolDesc;

// Entries marked with "*" have no standard URL scheme.
static ProtocolDesc protocolDescs[] = {
	{ &kSecAttrProtocolFTP, LKKCProtocolFTP, CFSTR("ftp") },
	{ &kSecAttrProtocolFTPAccount, LKKCProtocolFTPAccount, CFSTR("ftp-account") }, // *
	{ &kSecAttrProtocolHTTP, LKKCProtocolHTTP, CFSTR("http") },
	{ &kSecAttrProtocolIRC, LKKCProtocolIRC, CFSTR("irc") },
	{ &kSecAttrProtocolNNTP, LKKCProtocolNNTP, CFSTR("nntp") },
	{ &kSecAttrProtocolPOP3, LKKCProtocolPOP3, CFSTR("pop") },
	{ &kSecAttrProtocolSMTP, LKKCProtocolSMTP, CFSTR("smtp") }, // *
	{ &kSecAttrProtocolSOCKS, LKKCProtocolSOCKS, CFSTR("socks") }, // *
	{ &kSecAttrProtocolIMAP, LKKCProtocolIMAP, CFSTR("imap") },
	{ &kSecAttrProtocolLDAP, LKKCProtocolLDAP, CFSTR("ldap") },
	{ &kSecAttrProtocolAppleTalk, LKKCProtocolAppleTalk, CFSTR("afpat") }, // *, should be afp:/at/...
	{ &kSecAttrProtocolAFP, LKKCProtocolAFP, CFSTR("afp") },
	{ &kSecAttrProtocolTelnet, LKKCProtocolTelnet, CFSTR("telnet") },
	{ &kSecAttrProtocolSSH, LKKCProtocolSSH, CFSTR("ssh") },
	{ &kSecAttrProtocolFTPS, LKKCProtocolFTPS, CFSTR("ftps") },
	{ &kSecAttrProtocolHTTPS, LKKCProtocolHTTPS, CFSTR("https") },
	{ &kSecAttrProtocolHTTPProxy, LKKCProtocolHTTPProxy, CFSTR("http-proxy") }, // *
	{ &kSecAttrProtocolHTTPSProxy, LKKCProtocolHTTPSProxy, CFSTR("https-proxy") }, // *
	{ &kSecAttrProtocolFTPProxy, LKKCProtocolFTPProxy, CFSTR("ftp-proxy") }, // *
	{ &kSecAttrProtocolSMB, LKKCProtocolSMB, CFSTR("smb") },
	{ &kSecAttrProtocolRTSP, LKKCProtocolRTSP, CFSTR("rtsp") },
	{ &kSecAttrProtocolRTSPProxy, LKKCProtocolRTSPProxy, CFSTR("rtsp-proxy") }, // *
	{ &kSecAttrProtocolDAAP, LKKCProtocolDAAP, CFSTR("daap") },
	{ &kSecAttrProtocolEPPC, LKKCProtocolEPPC, CFSTR("eppc") }, // *
	{ &kSecAttrProtocolIPP, LKKCProtocolIPP, CFSTR("ipp") },
	{ &kSecAttrProtocolNNTPS, LKKCProtocolNNTPS, CFSTR("nntps") },
	{ &kSecAttrProtocolLDAPS, LKKCProtocolLDAPS, CFSTR("ldaps") },
	{ &kSecAttrProtocolTelnetS, LKKCProtocolTelnetS, CFSTR("telnets") },
	{ &kSecAttrProtocolIMAPS, LKKCProtocolIMAPS, CFSTR("imaps") },
	{ &kSecAttrProtocolIRCS, LKKCProtocolIRCS, CFSTR("ircs") },
	{ &kSecAttrProtocolPOP3S, LKKCProtocolPOP3S, CFSTR("pops") }
};

static const int cProtocolDescs = sizeof(protocolDescs) / sizeof(ProtocolDesc);

static ProtocolDesc *
ProtocolDescFromSecAttrProtocol(CFTypeRef sprotocol)
{
	if (sprotocol == NULL)
        return NULL;
    for (CFIndex i = 0; i < cProtocolDescs; i++) {
        if (CFEqual(sprotocol, *(protocolDescs[i].sprotocol)))
            return &protocolDescs[i];
    }
	return NULL;
}

static ProtocolDesc *
ProtocolDescFromLKKCProtocol(LKKCProtocol protocol)
{
    for (CFIndex i = 0; i < cProtocolDescs; i++) {
        if (protocol == protocolDescs[i].protocol)
            return &protocolDescs[i];
    }
	return NULL;
}

static ProtocolDesc *
ProtocolDescFromScheme(NSString *scheme)
{
    for (CFIndex i = 0; i < cProtocolDescs; i++) {
        if ([scheme isEqualToString:(NSString *)protocolDescs[i].scheme])
            return &protocolDescs[i];
    }
	return NULL;
}


#pragma mark - Authentication Types

typedef struct AuthenticationTypeDesc {
	const CFTypeRef *sauthenticationType;
    LKKCAuthenticationType authenticationType;
    CFStringRef description;
} AuthenticationTypeDesc;

static AuthenticationTypeDesc authenticationTypeDescs[] = {
	{ &kSecAttrAuthenticationTypeNTLM, LKKCAuthenticationTypeNTLM, CFSTR("NTLM") },
	{ &kSecAttrAuthenticationTypeMSN, LKKCAuthenticationTypeMSN, CFSTR("MSN") },
	{ &kSecAttrAuthenticationTypeDPA, LKKCAuthenticationTypeDPA, CFSTR("DPA") },
	{ &kSecAttrAuthenticationTypeRPA, LKKCAuthenticationTypeRPA, CFSTR("RPA") },
	{ &kSecAttrAuthenticationTypeHTTPBasic, LKKCAuthenticationTypeHTTPBasic, CFSTR("HTTPBasic") },
	{ &kSecAttrAuthenticationTypeHTTPDigest, LKKCAuthenticationTypeHTTPDigest, CFSTR("HTTPDigest") },
	{ &kSecAttrAuthenticationTypeHTMLForm, LKKCAuthenticationTypeHTMLForm, CFSTR("HTMLForm") },
	{ &kSecAttrAuthenticationTypeDefault, LKKCAuthenticationTypeDefault, CFSTR("Default") }
};

static const int cAuthenticationTypeDescs = sizeof(authenticationTypeDescs) / sizeof(AuthenticationTypeDesc);

static AuthenticationTypeDesc *
AuthenticationTypeDescFromSecAttrAuthenticationType(CFTypeRef sauthenticationType)
{
	if (sauthenticationType == NULL)
        return NULL;
    for (CFIndex i = 0; i < cAuthenticationTypeDescs; i++) {
        if (CFEqual(sauthenticationType, *(authenticationTypeDescs[i].sauthenticationType))) {
            return &authenticationTypeDescs[i];
        }
    }
	return NULL;    
}

static AuthenticationTypeDesc *
AuthenticationTypeDescFromLKKCAuthenticationType(LKKCAuthenticationType authenticationType)
{
    for (CFIndex i = 0; i < cAuthenticationTypeDescs; i++) {
        if (authenticationType == authenticationTypeDescs[i].authenticationType)
            return &authenticationTypeDescs[i];
    }
	return NULL;
}

#pragma mark - Implementation

@implementation LKKCInternetPassword

+ (void)load
{
    if (self != [LKKCInternetPassword class])
        return;
    [LKKCKeychainItem registerSubclass:self];
}

+ (CFTypeRef)itemClass
{
    return kSecClassInternetPassword;
}

+ (NSString *)urlSchemeFromProtocol:(LKKCProtocol)protocol
{
    ProtocolDesc *protocolDesc = ProtocolDescFromLKKCProtocol(protocol);
    if (protocolDesc == NULL)
        return @"any";
    return (NSString *)protocolDesc->scheme;
}

+ (LKKCProtocol)protocolFromURLScheme:(NSString *)scheme
{
    ProtocolDesc *protocolDesc = ProtocolDescFromScheme(scheme);
    if (protocolDesc == NULL)
        return LKKCProtocolAny;
    return protocolDesc->protocol;
}

+ (NSString *)stringFromAuthenticationType:(LKKCAuthenticationType)authenticationType
{
    AuthenticationTypeDesc *desc = AuthenticationTypeDescFromLKKCAuthenticationType(authenticationType);
    if (desc == NULL)
        return @"any";
    return (NSString *)desc->description;
}

+ (LKKCInternetPassword *)createPassword
{
    LKKCInternetPassword *item = [[LKKCInternetPassword alloc] initWithSecKeychainItem:NULL attributes:nil];
    return [item autorelease];
}

- (NSString *)description
{
    if (self.SecKeychainItem == NULL)
        return [NSString stringWithFormat:@"<%@ %p (deleted)>", [self className], self];
    
    NSMutableString *desc = [NSMutableString stringWithCapacity:256];
    [desc appendFormat:@"<%@ %p %@", [self className], self, self.url];

    if (self.authenticationType != LKKCAuthenticationTypeAny) {
        [desc appendFormat:@" type=%@", [[self class] stringFromAuthenticationType:self.authenticationType]];
    }
    if (self.securityDomain != nil) {
        [desc appendFormat:@" domain='%@'", self.securityDomain];
    }
    [desc appendString:@">"];
    return desc;
}

- (NSString *)label
{
    return [self valueForAttribute:kSecAttrLabel];
}

- (void)setLabel:(NSString *)label
{
    [self setAttribute:kSecAttrLabel toValue:label];
}

- (NSString *)kind
{
    return [self valueForAttribute:kSecAttrDescription];
}

- (void)setKind:(NSString *)kind
{
    [self setAttribute:kSecAttrDescription toValue:kind];
}

- (NSString *)comment
{
    return [self valueForAttribute:kSecAttrComment];
}

- (void)setComment:(NSString *)comment
{
    [self setAttribute:kSecAttrComment toValue:comment];
}

- (NSDate *)creationDate
{
    return [self valueForAttribute:kSecAttrCreationDate];
}

- (NSDate *)modificationDate
{
    return [self valueForAttribute:kSecAttrModificationDate];
}

- (BOOL)isInvisible
{
    CFBooleanRef value = (CFBooleanRef)[self valueForAttribute:kSecAttrIsInvisible];
    return (value ? CFBooleanGetValue(value) : NO);
}

- (void)setInvisible:(BOOL)invisible
{
    [self setAttribute:kSecAttrIsInvisible toValue:(invisible ? kCFBooleanTrue : kCFBooleanFalse)];
}

- (BOOL)isNegative
{
    CFBooleanRef value = (CFBooleanRef)[self valueForAttribute:kSecAttrIsNegative];
    return (value ? CFBooleanGetValue(value) : NO);
}

- (void)setNegative:(BOOL)negative
{
    [self setAttribute:kSecAttrIsNegative toValue:(negative ? kCFBooleanTrue : kCFBooleanFalse)];
}

- (NSString *)account 
{
    return [self valueForAttribute:kSecAttrAccount];
}

- (void)setAccount:(NSString *)account
{
    [self setAttribute:kSecAttrAccount toValue:account];
}

- (NSString *)securityDomain
{
    return [self valueForAttribute:kSecAttrSecurityDomain];
}

- (void)setSecurityDomain:(NSString *)securityDomain
{
    [self setAttribute:kSecAttrSecurityDomain toValue:securityDomain];
}

- (NSString *)server
{
    return [self valueForAttribute:kSecAttrServer];
}

- (void)setServer:(NSString *)server
{
    [self setAttribute:kSecAttrServer toValue:server];
}

- (LKKCProtocol)protocol 
{
    CFTypeRef sprotocol = [self valueForAttribute:kSecAttrProtocol];
    ProtocolDesc *protocolDesc = ProtocolDescFromSecAttrProtocol(sprotocol);
    if (protocolDesc == NULL)
        return LKKCProtocolAny;
    return protocolDesc->protocol;
}

- (void)setProtocol:(LKKCProtocol)protocol 
{
    ProtocolDesc *protocolDesc = ProtocolDescFromLKKCProtocol(protocol);
    if (protocolDesc == NULL)
        [self setAttribute:kSecAttrProtocol toValue:@"any"]; // will map to kSecProtocolTypeAny
    else
        [self setAttribute:kSecAttrProtocol toValue:*(protocolDesc->sprotocol)];
}

- (LKKCAuthenticationType)authenticationType
{
    CFTypeRef sauthenticationType = [self valueForAttribute:kSecAttrAuthenticationType];
    AuthenticationTypeDesc *desc = AuthenticationTypeDescFromSecAttrAuthenticationType(sauthenticationType);
    if (desc == NULL)
        return LKKCAuthenticationTypeAny;
    return desc->authenticationType;
}

- (void)setAuthenticationType:(LKKCAuthenticationType)authenticationType
{
    AuthenticationTypeDesc *desc = AuthenticationTypeDescFromLKKCAuthenticationType(authenticationType);
    if (desc == NULL)
        [self setAttribute:kSecAttrAuthenticationType toValue:@"any"]; // will map to kSecAuthenticationTypeAny
    else
        [self setAttribute:kSecAttrAuthenticationType toValue:*(desc->sauthenticationType)];
}

- (int)port
{
    return [[self valueForAttribute:kSecAttrPort] intValue];
}

- (void)setPort:(int)port
{
    [self setAttribute:kSecAttrPort toValue:[NSNumber numberWithInt:port]];
}

- (NSString *)path
{
    return [self valueForAttribute:kSecAttrPath];
}

- (void)setPath:(NSString *)path
{
    [self setAttribute:kSecAttrPath toValue:path];
}

- (NSString *)password
{
    return [self passwordWithError:NULL];
}

- (NSString *)passwordWithError:(NSError **)error
{
    NSData *data = [self rawDataWithError:error];
    if (data == nil)
        return nil;
    NSString *password = [[NSString alloc] initWithBytes:[data bytes] length:[data length] encoding:NSUTF8StringEncoding];
    return [password autorelease];
}

- (void)setPassword:(NSString *)password 
{
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    [self setAttribute:kSecValueData toValue:data];
}

- (NSURL *)url 
{
    NSMutableString *string = [NSMutableString string];
    
    [string appendString:[self.class urlSchemeFromProtocol:self.protocol]];
    [string appendString:@"://"];
    
    NSString *username = self.account;
    if (username != nil) {
        CFStringRef escapedUsername = CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (CFStringRef)username, NULL, CFSTR(":/?#[]@"), kCFStringEncodingUTF8);
        [string appendFormat:@"%@@", (id)escapedUsername];
        CFRelease(escapedUsername);
    }
    
    NSString *host = self.server;
    CFStringRef escapedHost = CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (CFStringRef)host, NULL, CFSTR(":/?#[]@"), kCFStringEncodingUTF8);
    [string appendString:(NSString *)escapedHost];
    CFRelease(escapedHost);
    
    int port = self.port;
    if (port > 0) {
        [string appendFormat:@":%d", port];
    }
    
    NSString *path = self.path;
    if (path != nil) {
        CFStringRef escapedPath = CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (CFStringRef)path, NULL, CFSTR("?#[]"), kCFStringEncodingUTF8);
        [string appendString:(id)escapedPath];
        CFRelease(escapedPath);
    }
    
    return [NSURL URLWithString:string];
}

- (void)setUrl:(NSURL *)url 
{
    self.protocol = [self.class protocolFromURLScheme:url.scheme];
    self.account = url.user;
    if (url.password != nil) {
        self.password = url.password;
    }
    self.server = url.host;
    self.port = [url.port intValue];
    self.path = url.path;
    self.authenticationType = LKKCAuthenticationTypeAny;
    self.securityDomain = nil;
    if (url.password != nil)
        self.password = url.password;
}

@end
