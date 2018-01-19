#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "nan.h"

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "x13.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "Lyra2RE.h"
    #include "Lyra2.h"
    #include "Lyra2REV2.h"
    #include "Lyra2Z.h"
    #include "lbry.h"
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

using namespace node;
using namespace v8;

NAN_METHOD(lbry) {
    
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    lbry_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("lbry").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(lbry)).ToLocalChecked());
}

NODE_MODULE(multihashing, init)
