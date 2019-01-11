/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: sm.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "sm.pb-c.h"
void   bool_value__init
                     (BoolValue         *message)
{
  static BoolValue init_value = BOOL_VALUE__INIT;
  *message = init_value;
}
size_t bool_value__get_packed_size
                     (const BoolValue *message)
{
  assert(message->base.descriptor == &bool_value__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t bool_value__pack
                     (const BoolValue *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &bool_value__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t bool_value__pack_to_buffer
                     (const BoolValue *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &bool_value__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
BoolValue *
       bool_value__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (BoolValue *)
     protobuf_c_message_unpack (&bool_value__descriptor,
                                allocator, len, data);
}
void   bool_value__free_unpacked
                     (BoolValue *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &bool_value__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   int_value__init
                     (IntValue         *message)
{
  static IntValue init_value = INT_VALUE__INIT;
  *message = init_value;
}
size_t int_value__get_packed_size
                     (const IntValue *message)
{
  assert(message->base.descriptor == &int_value__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t int_value__pack
                     (const IntValue *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &int_value__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t int_value__pack_to_buffer
                     (const IntValue *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &int_value__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
IntValue *
       int_value__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (IntValue *)
     protobuf_c_message_unpack (&int_value__descriptor,
                                allocator, len, data);
}
void   int_value__free_unpacked
                     (IntValue *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &int_value__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   str_value__init
                     (StrValue         *message)
{
  static StrValue init_value = STR_VALUE__INIT;
  *message = init_value;
}
size_t str_value__get_packed_size
                     (const StrValue *message)
{
  assert(message->base.descriptor == &str_value__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t str_value__pack
                     (const StrValue *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &str_value__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t str_value__pack_to_buffer
                     (const StrValue *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &str_value__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
StrValue *
       str_value__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (StrValue *)
     protobuf_c_message_unpack (&str_value__descriptor,
                                allocator, len, data);
}
void   str_value__free_unpacked
                     (StrValue *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &str_value__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   bytes_value__init
                     (BytesValue         *message)
{
  static BytesValue init_value = BYTES_VALUE__INIT;
  *message = init_value;
}
size_t bytes_value__get_packed_size
                     (const BytesValue *message)
{
  assert(message->base.descriptor == &bytes_value__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t bytes_value__pack
                     (const BytesValue *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &bytes_value__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t bytes_value__pack_to_buffer
                     (const BytesValue *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &bytes_value__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
BytesValue *
       bytes_value__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (BytesValue *)
     protobuf_c_message_unpack (&bytes_value__descriptor,
                                allocator, len, data);
}
void   bytes_value__free_unpacked
                     (BytesValue *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &bytes_value__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   key_pair__init
                     (KeyPair         *message)
{
  static KeyPair init_value = KEY_PAIR__INIT;
  *message = init_value;
}
size_t key_pair__get_packed_size
                     (const KeyPair *message)
{
  assert(message->base.descriptor == &key_pair__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t key_pair__pack
                     (const KeyPair *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &key_pair__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t key_pair__pack_to_buffer
                     (const KeyPair *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &key_pair__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
KeyPair *
       key_pair__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (KeyPair *)
     protobuf_c_message_unpack (&key_pair__descriptor,
                                allocator, len, data);
}
void   key_pair__free_unpacked
                     (KeyPair *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &key_pair__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   dev_status__init
                     (DevStatus         *message)
{
  static DevStatus init_value = DEV_STATUS__INIT;
  *message = init_value;
}
size_t dev_status__get_packed_size
                     (const DevStatus *message)
{
  assert(message->base.descriptor == &dev_status__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t dev_status__pack
                     (const DevStatus *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &dev_status__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t dev_status__pack_to_buffer
                     (const DevStatus *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &dev_status__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
DevStatus *
       dev_status__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (DevStatus *)
     protobuf_c_message_unpack (&dev_status__descriptor,
                                allocator, len, data);
}
void   dev_status__free_unpacked
                     (DevStatus *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &dev_status__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   ctx_info__init
                     (CtxInfo         *message)
{
  static CtxInfo init_value = CTX_INFO__INIT;
  *message = init_value;
}
size_t ctx_info__get_packed_size
                     (const CtxInfo *message)
{
  assert(message->base.descriptor == &ctx_info__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t ctx_info__pack
                     (const CtxInfo *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &ctx_info__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t ctx_info__pack_to_buffer
                     (const CtxInfo *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &ctx_info__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
CtxInfo *
       ctx_info__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (CtxInfo *)
     protobuf_c_message_unpack (&ctx_info__descriptor,
                                allocator, len, data);
}
void   ctx_info__free_unpacked
                     (CtxInfo *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &ctx_info__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   response__init
                     (Response         *message)
{
  static Response init_value = RESPONSE__INIT;
  *message = init_value;
}
size_t response__get_packed_size
                     (const Response *message)
{
  assert(message->base.descriptor == &response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t response__pack
                     (const Response *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t response__pack_to_buffer
                     (const Response *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Response *
       response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Response *)
     protobuf_c_message_unpack (&response__descriptor,
                                allocator, len, data);
}
void   response__free_unpacked
                     (Response *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor bool_value__field_descriptors[1] =
{
  {
    "value",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(BoolValue, has_value),
    offsetof(BoolValue, value),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned bool_value__field_indices_by_name[] = {
  0,   /* field[0] = value */
};
static const ProtobufCIntRange bool_value__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor bool_value__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "BoolValue",
  "BoolValue",
  "BoolValue",
  "",
  sizeof(BoolValue),
  1,
  bool_value__field_descriptors,
  bool_value__field_indices_by_name,
  1,  bool_value__number_ranges,
  (ProtobufCMessageInit) bool_value__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor int_value__field_descriptors[1] =
{
  {
    "value",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(IntValue, has_value),
    offsetof(IntValue, value),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned int_value__field_indices_by_name[] = {
  0,   /* field[0] = value */
};
static const ProtobufCIntRange int_value__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor int_value__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "IntValue",
  "IntValue",
  "IntValue",
  "",
  sizeof(IntValue),
  1,
  int_value__field_descriptors,
  int_value__field_indices_by_name,
  1,  int_value__number_ranges,
  (ProtobufCMessageInit) int_value__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor str_value__field_descriptors[1] =
{
  {
    "value",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(StrValue, value),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned str_value__field_indices_by_name[] = {
  0,   /* field[0] = value */
};
static const ProtobufCIntRange str_value__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor str_value__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "StrValue",
  "StrValue",
  "StrValue",
  "",
  sizeof(StrValue),
  1,
  str_value__field_descriptors,
  str_value__field_indices_by_name,
  1,  str_value__number_ranges,
  (ProtobufCMessageInit) str_value__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor bytes_value__field_descriptors[1] =
{
  {
    "value",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(BytesValue, has_value),
    offsetof(BytesValue, value),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned bytes_value__field_indices_by_name[] = {
  0,   /* field[0] = value */
};
static const ProtobufCIntRange bytes_value__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor bytes_value__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "BytesValue",
  "BytesValue",
  "BytesValue",
  "",
  sizeof(BytesValue),
  1,
  bytes_value__field_descriptors,
  bytes_value__field_indices_by_name,
  1,  bytes_value__number_ranges,
  (ProtobufCMessageInit) bytes_value__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor key_pair__field_descriptors[2] =
{
  {
    "public_key",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(KeyPair, public_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "private_key",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(KeyPair, private_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned key_pair__field_indices_by_name[] = {
  1,   /* field[1] = private_key */
  0,   /* field[0] = public_key */
};
static const ProtobufCIntRange key_pair__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor key_pair__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "KeyPair",
  "KeyPair",
  "KeyPair",
  "",
  sizeof(KeyPair),
  2,
  key_pair__field_descriptors,
  key_pair__field_indices_by_name,
  1,  key_pair__number_ranges,
  (ProtobufCMessageInit) key_pair__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor dev_status__field_descriptors[8] =
{
  {
    "index",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(DevStatus, has_index),
    offsetof(DevStatus, index),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "opened",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(DevStatus, has_opened),
    offsetof(DevStatus, opened),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "logged_in",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(DevStatus, has_logged_in),
    offsetof(DevStatus, logged_in),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pipes_count",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(DevStatus, has_pipes_count),
    offsetof(DevStatus, pipes_count),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "free_pipes_count",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(DevStatus, has_free_pipes_count),
    offsetof(DevStatus, free_pipes_count),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "secret_key_count",
    6,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(DevStatus, has_secret_key_count),
    offsetof(DevStatus, secret_key_count),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "public_key_count",
    7,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(DevStatus, has_public_key_count),
    offsetof(DevStatus, public_key_count),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "private_key_count",
    8,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(DevStatus, has_private_key_count),
    offsetof(DevStatus, private_key_count),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned dev_status__field_indices_by_name[] = {
  4,   /* field[4] = free_pipes_count */
  0,   /* field[0] = index */
  2,   /* field[2] = logged_in */
  1,   /* field[1] = opened */
  3,   /* field[3] = pipes_count */
  7,   /* field[7] = private_key_count */
  6,   /* field[6] = public_key_count */
  5,   /* field[5] = secret_key_count */
};
static const ProtobufCIntRange dev_status__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 8 }
};
const ProtobufCMessageDescriptor dev_status__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "DevStatus",
  "DevStatus",
  "DevStatus",
  "",
  sizeof(DevStatus),
  8,
  dev_status__field_descriptors,
  dev_status__field_indices_by_name,
  1,  dev_status__number_ranges,
  (ProtobufCMessageInit) dev_status__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor ctx_info__field_descriptors[3] =
{
  {
    "protect_key",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(CtxInfo, has_protect_key),
    offsetof(CtxInfo, protect_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "device_count",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(CtxInfo, has_device_count),
    offsetof(CtxInfo, device_count),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "api_version",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(CtxInfo, api_version),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned ctx_info__field_indices_by_name[] = {
  2,   /* field[2] = api_version */
  1,   /* field[1] = device_count */
  0,   /* field[0] = protect_key */
};
static const ProtobufCIntRange ctx_info__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor ctx_info__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "CtxInfo",
  "CtxInfo",
  "CtxInfo",
  "",
  sizeof(CtxInfo),
  3,
  ctx_info__field_descriptors,
  ctx_info__field_indices_by_name,
  1,  ctx_info__number_ranges,
  (ProtobufCMessageInit) ctx_info__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor response__field_descriptors[9] =
{
  {
    "code",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(Response, has_code),
    offsetof(Response, code),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "msg",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Response, msg),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bool_value",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Response, data_case),
    offsetof(Response, bool_value),
    &bool_value__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "int_value",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Response, data_case),
    offsetof(Response, int_value),
    &int_value__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "str_value",
    6,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Response, data_case),
    offsetof(Response, str_value),
    &str_value__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bytes_value",
    7,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Response, data_case),
    offsetof(Response, bytes_value),
    &bytes_value__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "key_pair",
    8,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Response, data_case),
    offsetof(Response, key_pair),
    &key_pair__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "device_status",
    9,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Response, data_case),
    offsetof(Response, device_status),
    &dev_status__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ctx_info",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Response, data_case),
    offsetof(Response, ctx_info),
    &ctx_info__descriptor,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_ONEOF,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned response__field_indices_by_name[] = {
  2,   /* field[2] = bool_value */
  5,   /* field[5] = bytes_value */
  0,   /* field[0] = code */
  8,   /* field[8] = ctx_info */
  7,   /* field[7] = device_status */
  3,   /* field[3] = int_value */
  6,   /* field[6] = key_pair */
  1,   /* field[1] = msg */
  4,   /* field[4] = str_value */
};
static const ProtobufCIntRange response__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 4, 2 },
  { 0, 9 }
};
const ProtobufCMessageDescriptor response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "Response",
  "Response",
  "Response",
  "",
  sizeof(Response),
  9,
  response__field_descriptors,
  response__field_indices_by_name,
  2,  response__number_ranges,
  (ProtobufCMessageInit) response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
