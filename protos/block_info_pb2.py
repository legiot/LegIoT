# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: block_info.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='block_info.proto',
  package='',
  syntax='proto3',
  serialized_options=_b('\n\034sawtooth.block_info.protobufP\001Z\016block_info_pb2'),
  serialized_pb=_b('\n\x10\x62lock_info.proto\"k\n\x0f\x42lockInfoConfig\x12\x14\n\x0clatest_block\x18\x01 \x01(\x04\x12\x14\n\x0coldest_block\x18\x02 \x01(\x04\x12\x14\n\x0ctarget_count\x18\x03 \x01(\x04\x12\x16\n\x0esync_tolerance\x18\x04 \x01(\x04\"\x81\x01\n\tBlockInfo\x12\x11\n\tblock_num\x18\x01 \x01(\x04\x12\x19\n\x11previous_block_id\x18\x02 \x01(\t\x12\x19\n\x11signer_public_key\x18\x03 \x01(\t\x12\x18\n\x10header_signature\x18\x04 \x01(\t\x12\x11\n\ttimestamp\x18\x05 \x01(\x04\"W\n\x0c\x42lockInfoTxn\x12\x19\n\x05\x62lock\x18\x01 \x01(\x0b\x32\n.BlockInfo\x12\x14\n\x0ctarget_count\x18\x02 \x01(\x04\x12\x16\n\x0esync_tolerance\x18\x03 \x01(\x04\x42\x30\n\x1csawtooth.block_info.protobufP\x01Z\x0e\x62lock_info_pb2b\x06proto3')
)




_BLOCKINFOCONFIG = _descriptor.Descriptor(
  name='BlockInfoConfig',
  full_name='BlockInfoConfig',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='latest_block', full_name='BlockInfoConfig.latest_block', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='oldest_block', full_name='BlockInfoConfig.oldest_block', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='target_count', full_name='BlockInfoConfig.target_count', index=2,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sync_tolerance', full_name='BlockInfoConfig.sync_tolerance', index=3,
      number=4, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=20,
  serialized_end=127,
)


_BLOCKINFO = _descriptor.Descriptor(
  name='BlockInfo',
  full_name='BlockInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='block_num', full_name='BlockInfo.block_num', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='previous_block_id', full_name='BlockInfo.previous_block_id', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signer_public_key', full_name='BlockInfo.signer_public_key', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='header_signature', full_name='BlockInfo.header_signature', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='BlockInfo.timestamp', index=4,
      number=5, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=130,
  serialized_end=259,
)


_BLOCKINFOTXN = _descriptor.Descriptor(
  name='BlockInfoTxn',
  full_name='BlockInfoTxn',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='block', full_name='BlockInfoTxn.block', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='target_count', full_name='BlockInfoTxn.target_count', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sync_tolerance', full_name='BlockInfoTxn.sync_tolerance', index=2,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=261,
  serialized_end=348,
)

_BLOCKINFOTXN.fields_by_name['block'].message_type = _BLOCKINFO
DESCRIPTOR.message_types_by_name['BlockInfoConfig'] = _BLOCKINFOCONFIG
DESCRIPTOR.message_types_by_name['BlockInfo'] = _BLOCKINFO
DESCRIPTOR.message_types_by_name['BlockInfoTxn'] = _BLOCKINFOTXN
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

BlockInfoConfig = _reflection.GeneratedProtocolMessageType('BlockInfoConfig', (_message.Message,), dict(
  DESCRIPTOR = _BLOCKINFOCONFIG,
  __module__ = 'block_info_pb2'
  # @@protoc_insertion_point(class_scope:BlockInfoConfig)
  ))
_sym_db.RegisterMessage(BlockInfoConfig)

BlockInfo = _reflection.GeneratedProtocolMessageType('BlockInfo', (_message.Message,), dict(
  DESCRIPTOR = _BLOCKINFO,
  __module__ = 'block_info_pb2'
  # @@protoc_insertion_point(class_scope:BlockInfo)
  ))
_sym_db.RegisterMessage(BlockInfo)

BlockInfoTxn = _reflection.GeneratedProtocolMessageType('BlockInfoTxn', (_message.Message,), dict(
  DESCRIPTOR = _BLOCKINFOTXN,
  __module__ = 'block_info_pb2'
  # @@protoc_insertion_point(class_scope:BlockInfoTxn)
  ))
_sym_db.RegisterMessage(BlockInfoTxn)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
