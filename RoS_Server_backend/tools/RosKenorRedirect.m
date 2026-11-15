// RosKenorRedirect.m
// Combined NSURLProtocol (NSURLConnection + NSURLSession), CFNetwork,
// libcurl (curl_easy_setopt via fishhook), and BSD connect() + SecTrust
// interceptor for Rules of Survival (Ros Kenor).
//
// Compile on macOS with Xcode CLI tools:
//   clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//     -miphoneos-version-min=12.0 -shared -fobjc-arc -Wno-deprecated-declarations \
//     -framework Foundation -framework WebKit -framework Security -framework CFNetwork \
//     -install_name @executable_path/Frameworks/RosKenorRedirect.dylib \
//     -o RosKenorRedirect.dylib \
//     RoS_Server_backend/tools/RosKenorRedirect.m RoS_Server_backend/tools/fishhook.c

#import <CFNetwork/CFNetwork.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "fishhook.h"

static NSString *const kRosKenorBaseURL = @"https://api.stillchooseyou.site";
static NSString *const kHandledKey = @"RosKenorRedirectHandled";

static const char *kOldServerIP = "172.65.54.209";
static const char *kAltGameIP = "172.104.170.200";
static const char *kNeteaseEdgeIP = "223.252.216.48";
static const char *kLocalGatewayIP = "192.168.8.42";
static const uint16_t kLocalHttpsPort = 8443;
static const uint16_t kLocalHttpPort = 8080;
static const uint16_t kLocalTcpPort = 19000;

// libcurl option constants (avoiding dependency on <curl/curl.h> in iOS SDK)
#define ROS_CURLOPT_SSL_VERIFYPEER 64
#define ROS_CURLOPT_SSL_VERIFYHOST 81
#define ROS_CURLOPT_URL 10002

@interface RosKenorRedirectProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSessionDataTask *dataTask;
+ (BOOL)shouldRedirectHost:(NSString *)host;
+ (NSURL *)rewrittenURLForURL:(NSURL *)url;
+ (NSURLRequest *)rewrittenRequestForRequest:(NSURLRequest *)request;
@end

// Original function pointers resolved before fishhook rebinding
static int (*orig_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
static int (*orig_curl_easy_setopt)(void *, int, ...) = NULL;
static CFHTTPMessageRef (*orig_CFHTTPMessageCreateRequest)(
    CFAllocatorRef, CFStringRef, CFURLRef, CFStringRef) = NULL;

static BOOL ros_should_redirect_ipv4(in_addr_t s_addr) {
    return s_addr == inet_addr(kOldServerIP) ||
           s_addr == inet_addr(kAltGameIP) ||
           s_addr == inet_addr(kNeteaseEdgeIP);
}

static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int (*real_connect)(int, const struct sockaddr *, socklen_t) = orig_connect;
    if (!real_connect) {
        real_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
    }
    if (addr && addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;
        uint16_t port = ntohs(in_addr->sin_port);
        in_addr_t local_ip = inet_addr(kLocalGatewayIP);

        if (ros_should_redirect_ipv4(in_addr->sin_addr.s_addr) ||
            (in_addr->sin_addr.s_addr == local_ip &&
             (port == 443 || port == 80 || port == 19003 || port == 19009 || port == 20011))) {
            uint16_t mapped_port = port;
            if (port == 443) {
                mapped_port = kLocalHttpsPort;
            } else if (port == 80) {
                mapped_port = kLocalHttpPort;
            } else if (port == 19000 || port == 19003 || port == 19009 || port == 20011) {
                mapped_port = kLocalTcpPort;
            }
            struct sockaddr_in gw = *in_addr;
            gw.sin_addr.s_addr = local_ip;
            gw.sin_port = htons(mapped_port);
            char orig_ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &in_addr->sin_addr, orig_ip, sizeof(orig_ip));
            NSLog(@"[RosKenorRedirect] connect %s:%u -> %s:%u",
                  orig_ip, port, kLocalGatewayIP, mapped_port);
            return real_connect(sockfd, (const struct sockaddr *)&gw, sizeof(gw));
        }
    }
    return real_connect(sockfd, addr, addrlen);
}

static int hooked_getaddrinfo(
    const char *node,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res) {
    int (*real_gai)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = orig_getaddrinfo;
    if (!real_gai) {
        real_gai = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))dlsym(RTLD_NEXT, "getaddrinfo");
    }
    if (node != NULL) {
        @autoreleasepool {
            NSString *host = [NSString stringWithUTF8String:node];
            if ([RosKenorRedirectProtocol shouldRedirectHost:host]) {
                NSLog(@"[RosKenorRedirect] getaddrinfo %@ -> %s", host, kLocalGatewayIP);
                return real_gai(kLocalGatewayIP, service, hints, res);
            }
        }
    }
    return real_gai(node, service, hints, res);
}

static OSStatus hooked_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    (void)trust;
    if (result) {
        *result = kSecTrustResultProceed;
    }
    return errSecSuccess;
}

static bool hooked_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    (void)trust;
    if (error) {
        *error = NULL;
    }
    return true;
}

static int hooked_curl_easy_setopt(void *curl, int option, ...) {
    int (*real_setopt)(void *, int, ...) = orig_curl_easy_setopt;
    if (!real_setopt) {
        real_setopt = (int (*)(void *, int, ...))dlsym(RTLD_NEXT, "curl_easy_setopt");
    }
    if (!real_setopt) {
        return 0;
    }

    va_list ap;
    va_start(ap, option);

    if (option == ROS_CURLOPT_URL) {
        const char *raw_url = va_arg(ap, const char *);
        va_end(ap);
        if (raw_url != NULL) {
            @autoreleasepool {
                NSString *urlStr = [NSString stringWithUTF8String:raw_url];
                NSURL *parsed = urlStr ? [NSURL URLWithString:urlStr] : nil;
                NSURL *rewritten = parsed ? [RosKenorRedirectProtocol rewrittenURLForURL:parsed] : nil;
                if (rewritten != nil) {
                    const char *new_cstr = rewritten.absoluteString.UTF8String;
                    int rc = real_setopt(curl, option, new_cstr);
                    real_setopt(curl, ROS_CURLOPT_SSL_VERIFYPEER, 0L);
                    real_setopt(curl, ROS_CURLOPT_SSL_VERIFYHOST, 0L);
                    return rc;
                }
            }
        }
        return real_setopt(curl, option, raw_url);
    }

    if (option == ROS_CURLOPT_SSL_VERIFYPEER || option == ROS_CURLOPT_SSL_VERIFYHOST) {
        (void)va_arg(ap, long);
        va_end(ap);
        return real_setopt(curl, option, 0L);
    }

    uintptr_t arg = va_arg(ap, uintptr_t);
    va_end(ap);
    return real_setopt(curl, option, arg);
}

static CFHTTPMessageRef hooked_CFHTTPMessageCreateRequest(
    CFAllocatorRef alloc, CFStringRef requestMethod, CFURLRef url, CFStringRef httpVersion) {
    CFURLRef targetURL = url;
    if (url != NULL) {
        @autoreleasepool {
            NSURL *nsURL = (__bridge NSURL *)url;
            NSURL *rewritten = [RosKenorRedirectProtocol rewrittenURLForURL:nsURL];
            if (rewritten != nil) {
                targetURL = (__bridge CFURLRef)rewritten;
                if (orig_CFHTTPMessageCreateRequest) {
                    return orig_CFHTTPMessageCreateRequest(alloc, requestMethod, targetURL, httpVersion);
                }
                return CFHTTPMessageCreateRequest(alloc, requestMethod, targetURL, httpVersion);
            }
        }
    }
    if (orig_CFHTTPMessageCreateRequest) {
        return orig_CFHTTPMessageCreateRequest(alloc, requestMethod, targetURL, httpVersion);
    }
    return CFHTTPMessageCreateRequest(alloc, requestMethod, targetURL, httpVersion);
}

@implementation RosKenorRedirectProtocol

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Resolve real implementations BEFORE fishhook walks all images, so
        // unrelated framework lazy stub_helpers never overwrite our orig_* pointers.
        orig_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_DEFAULT, "connect");
        orig_getaddrinfo = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **))dlsym(RTLD_DEFAULT, "getaddrinfo");
        orig_curl_easy_setopt = (int (*)(void *, int, ...))dlsym(RTLD_DEFAULT, "curl_easy_setopt");
        orig_CFHTTPMessageCreateRequest = (CFHTTPMessageRef (*)(CFAllocatorRef, CFStringRef, CFURLRef, CFStringRef))dlsym(RTLD_DEFAULT, "CFHTTPMessageCreateRequest");

        struct rebinding rebindings[] = {
            {"connect", (void *)hooked_connect, NULL},
            {"getaddrinfo", (void *)hooked_getaddrinfo, NULL},
            {"SecTrustEvaluate", (void *)hooked_SecTrustEvaluate, NULL},
            {"SecTrustEvaluateWithError", (void *)hooked_SecTrustEvaluateWithError, NULL},
            {"curl_easy_setopt", (void *)hooked_curl_easy_setopt, NULL},
            {"CFHTTPMessageCreateRequest", (void *)hooked_CFHTTPMessageCreateRequest, NULL},
        };
        rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
        NSLog(@"[RosKenorRedirect] loaded and rebound connect/getaddrinfo/SecTrust/CFHTTPMessage (orig_connect=%p)", (void *)orig_connect);

        [NSURLProtocol registerClass:[RosKenorRedirectProtocol class]];
        [self swizzleSessionConfiguration];
        [self swizzleURLSessionTasks];
    });
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

+ (void)swizzleURLSessionTasks {
    Class cls = [NSURLSession class];

    Method reqMethod = class_getInstanceMethod(cls, @selector(dataTaskWithRequest:));
    if (reqMethod) {
        IMP origReqIMP = method_getImplementation(reqMethod);
        IMP newReqIMP = imp_implementationWithBlock(^NSURLSessionDataTask *(id selfObj, NSURLRequest *req) {
            NSURLRequest *rewritten = [RosKenorRedirectProtocol rewrittenRequestForRequest:req];
            return ((NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *))origReqIMP)(
                selfObj, @selector(dataTaskWithRequest:), rewritten ?: req);
        });
        method_setImplementation(reqMethod, newReqIMP);
    }

    Method urlMethod = class_getInstanceMethod(cls, @selector(dataTaskWithURL:));
    if (urlMethod) {
        IMP origURLIMP = method_getImplementation(urlMethod);
        IMP newURLIMP = imp_implementationWithBlock(^NSURLSessionDataTask *(id selfObj, NSURL *url) {
            NSURL *rewritten = [RosKenorRedirectProtocol rewrittenURLForURL:url];
            return ((NSURLSessionDataTask *(*)(id, SEL, NSURL *))origURLIMP)(
                selfObj, @selector(dataTaskWithURL:), rewritten ?: url);
        });
        method_setImplementation(urlMethod, newURLIMP);
    }
}

+ (BOOL)shouldRedirectHost:(NSString *)host {
    if (!host || host.length == 0) return NO;
    NSString *lower = host.lowercaseString;
    if ([lower isEqualToString:@"api.stillchooseyou.site"]) {
        return NO;
    }
    NSSet<NSString *> *exact = [NSSet setWithObjects:
        @"172.65.54.209",
        @"172.104.170.200",
        @"223.252.216.48",
        @"api.roslegacy.net",
        @"cdn.mobile.roslegacy.net",
        @"mirae-labs.com",
        @"topup.mythgames.net",
        @"easebar.com",
        @"netease.com",
        @"163.com",
        nil];
    if ([exact containsObject:lower]) return YES;
    return [lower hasSuffix:@".roslegacy.net"] ||
           [lower hasSuffix:@".mirae-labs.com"] ||
           [lower hasSuffix:@".easebar.com"] ||
           [lower hasSuffix:@".netease.com"] ||
           [lower hasSuffix:@".163.com"];
}

+ (NSURL *)rewrittenURLForURL:(NSURL *)url {
    if (!url || ![self shouldRedirectHost:url.host]) {
        return nil;
    }
    NSURLComponents *comps = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    NSURLComponents *target = [NSURLComponents componentsWithString:kRosKenorBaseURL];
    if (!comps || !target) {
        return nil;
    }
    comps.scheme = target.scheme;
    comps.host = target.host;
    comps.port = target.port;
    if ([url.host.lowercaseString containsString:@"mirae-labs.com"] &&
        [comps.path isEqualToString:@"/register"]) {
        comps.path = @"/login";
    }
    return comps.URL;
}

+ (NSURLRequest *)rewrittenRequestForRequest:(NSURLRequest *)request {
    NSURL *rewritten = [self rewrittenURLForURL:request.URL];
    if (!rewritten) {
        return nil;
    }
    NSMutableURLRequest *mutableReq = [request mutableCopy];
    mutableReq.URL = rewritten;
    return mutableReq;
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

    NSURL *rewritten = [RosKenorRedirectProtocol rewrittenURLForURL:mutableReq.URL];
    if (rewritten) {
        mutableReq.URL = rewritten;
    }

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
