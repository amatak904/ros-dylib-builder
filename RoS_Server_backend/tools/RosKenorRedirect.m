// RosKenorRedirect.m
// Combined NSURLProtocol (NSURLConnection + NSURLSession) and BSD connect()
// socket interceptor for Ros Kenor.
//
// Compile on macOS with Xcode CLI tools:
//   clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//     -miphoneos-version-min=12.0 -shared -fobjc-arc \
//     -framework Foundation -framework WebKit \
//     -install_name @executable_path/Frameworks/RosKenorRedirect.dylib \
//     -o RosKenorRedirect.dylib RoS_Server_backend/tools/RosKenorRedirect.m

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

static NSString *const kRosKenorBaseURL = @"https://api.stillchooseyou.site";
static NSString *const kHandledKey = @"RosKenorRedirectHandled";

static const char *kOldServerIP = "172.65.54.209";
static const char *kTunnelDomain = "api.stillchooseyou.site";
static const char *kLocalGatewayIP = "192.168.8.42";
static const uint16_t kLocalHttpsPort = 8443;
static const uint16_t kLocalTcpPort = 19000;

#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { const void *replacement; const void *replacee; } \
    _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement, (const void *)(unsigned long)&_replacee \
    };

static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr && addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;
        if (in_addr->sin_addr.s_addr == inet_addr(kOldServerIP)) {
            uint16_t port = ntohs(in_addr->sin_port);
            if (port == 443) {
                struct addrinfo hints;
                struct addrinfo *res = NULL;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                if (getaddrinfo(kTunnelDomain, "443", &hints, &res) == 0 && res != NULL) {
                    int rc = connect(sockfd, res->ai_addr, res->ai_addrlen);
                    freeaddrinfo(res);
                    return rc;
                }
                struct sockaddr_in fallback = *in_addr;
                fallback.sin_addr.s_addr = inet_addr(kLocalGatewayIP);
                fallback.sin_port = htons(kLocalHttpsPort);
                return connect(sockfd, (const struct sockaddr *)&fallback, sizeof(fallback));
            } else if (port == 19000) {
                struct sockaddr_in tcp_gw = *in_addr;
                tcp_gw.sin_addr.s_addr = inet_addr(kLocalGatewayIP);
                tcp_gw.sin_port = htons(kLocalTcpPort);
                return connect(sockfd, (const struct sockaddr *)&tcp_gw, sizeof(tcp_gw));
            }
        }
    }
    return connect(sockfd, addr, addrlen);
}

static OSStatus hooked_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) {
        *result = kSecTrustResultProceed;
    }
    return errSecSuccess;
}

static bool hooked_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (error) {
        *error = NULL;
    }
    return true;
}

DYLD_INTERPOSE(hooked_connect, connect)
DYLD_INTERPOSE(hooked_SecTrustEvaluate, SecTrustEvaluate)
DYLD_INTERPOSE(hooked_SecTrustEvaluateWithError, SecTrustEvaluateWithError)

@interface RosKenorRedirectProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSessionDataTask *dataTask;
@end

@implementation RosKenorRedirectProtocol

+ (void)load {
    [NSURLProtocol registerClass:[RosKenorRedirectProtocol class]];
    [self swizzleSessionConfiguration];
}

+ (void)swizzleSessionConfiguration {
    Class cls = NSClassFromString(@"__NSCFURLSessionConfiguration") ?: [NSURLSessionConfiguration class];
    Method orig = class_getInstanceMethod(cls, @selector(protocolClasses));
    if (!orig) return;

    IMP origIMP = method_getImplementation(orig);
    IMP newIMP = imp_implementationWithBlock(^NSArray<Class> *(id selfObj) {
        NSArray<Class> *classes = ((NSArray<Class> *(*)(id, SEL))origIMP)(selfObj, @selector(protocolClasses));
        NSMutableArray<Class> *mut = classes ? [classes mutableCopy] : [NSMutableArray array];
        if (![mut containsObject:[RosKenorRedirectProtocol class]]) {
            [mut insertObject:[RosKenorRedirectProtocol class] atIndex:0];
        }
        return mut;
    });
    method_setImplementation(orig, newIMP);
}

+ (BOOL)shouldRedirectHost:(NSString *)host {
    if (!host) return NO;
    NSString *lower = host.lowercaseString;
    NSSet<NSString *> *exact = [NSSet setWithObjects:
        @"172.65.54.209",
        @"api.roslegacy.net",
        @"cdn.mobile.roslegacy.net",
        @"mirae-labs.com",
        @"topup.mythgames.net",
        @"mgbsdknaeast.matrix.easebar.com",
        @"data-detect.nie.easebar.com",
        @"unisdk.proxima.nie.easebar.com",
        @"unisdk.update.easebar.com",
        @"appdump.nie.easebar.com",
        @"applog.matrix.easebar.com",
        nil];
    if ([exact containsObject:lower]) return YES;
    return [lower hasSuffix:@".roslegacy.net"] ||
           [lower hasSuffix:@".mirae-labs.com"] ||
           [lower hasSuffix:@".easebar.com"] ||
           [lower hasSuffix:@".cc.163.com"];
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:kHandledKey inRequest:request]) {
        return NO;
    }
    return [self shouldRedirectHost:request.URL.host];
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSMutableURLRequest *mutableReq = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:kHandledKey inRequest:mutableReq];

    NSURLComponents *comps = [NSURLComponents componentsWithURL:mutableReq.URL resolvingAgainstBaseURL:NO];
    NSURLComponents *target = [NSURLComponents componentsWithString:kRosKenorBaseURL];
    comps.scheme = target.scheme;
    comps.host = target.host;
    comps.port = target.port;
    if ([mutableReq.URL.host.lowercaseString containsString:@"mirae-labs.com"] &&
        [comps.path isEqualToString:@"/register"]) {
        comps.path = @"/login";
    }
    mutableReq.URL = comps.URL;

    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:self
                                                     delegateQueue:nil];
    self.dataTask = [session dataTaskWithRequest:mutableReq];
    [self.dataTask resume];
}

- (void)stopLoading {
    [self.dataTask cancel];
    self.dataTask = nil;
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] &&
        challenge.protectionSpace.serverTrust != NULL) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
        return;
    }
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
    } else {
        [self.client URLProtocolDidFinishLoading:self];
    }
}

@end
