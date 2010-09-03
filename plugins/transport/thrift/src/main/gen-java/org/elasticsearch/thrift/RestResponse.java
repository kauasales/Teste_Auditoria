/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 */
package org.elasticsearch.thrift;

import org.apache.thrift.*;
import org.apache.thrift.meta_data.EnumMetaData;
import org.apache.thrift.meta_data.FieldMetaData;
import org.apache.thrift.meta_data.FieldValueMetaData;
import org.apache.thrift.meta_data.MapMetaData;
import org.apache.thrift.protocol.*;

import java.nio.ByteBuffer;
import java.util.*;

public class RestResponse implements TBase<RestResponse, RestResponse._Fields>, java.io.Serializable, Cloneable {
    private static final TStruct STRUCT_DESC = new TStruct("RestResponse");

    private static final TField STATUS_FIELD_DESC = new TField("status", TType.I32, (short) 1);
    private static final TField HEADERS_FIELD_DESC = new TField("headers", TType.MAP, (short) 2);
    private static final TField BODY_FIELD_DESC = new TField("body", TType.STRING, (short) 3);

    /**
     * @see org.elasticsearch.thrift.Status
     */
    public Status status;
    public Map<String, String> headers;
    public ByteBuffer body;

    /**
     * The set of fields this struct contains, along with convenience methods for finding and manipulating them.
     */
    public enum _Fields implements TFieldIdEnum {
        /**
         * @see org.elasticsearch.thrift.Status
         */
        STATUS((short) 1, "status"),
        HEADERS((short) 2, "headers"),
        BODY((short) 3, "body");

        private static final Map<String, _Fields> byName = new HashMap<String, _Fields>();

        static {
            for (_Fields field : EnumSet.allOf(_Fields.class)) {
                byName.put(field.getFieldName(), field);
            }
        }

        /**
         * Find the _Fields constant that matches fieldId, or null if its not found.
         */
        public static _Fields findByThriftId(int fieldId) {
            switch (fieldId) {
                case 1: // STATUS
                    return STATUS;
                case 2: // HEADERS
                    return HEADERS;
                case 3: // BODY
                    return BODY;
                default:
                    return null;
            }
        }

        /**
         * Find the _Fields constant that matches fieldId, throwing an exception
         * if it is not found.
         */
        public static _Fields findByThriftIdOrThrow(int fieldId) {
            _Fields fields = findByThriftId(fieldId);
            if (fields == null) throw new IllegalArgumentException("Field " + fieldId + " doesn't exist!");
            return fields;
        }

        /**
         * Find the _Fields constant that matches name, or null if its not found.
         */
        public static _Fields findByName(String name) {
            return byName.get(name);
        }

        private final short _thriftId;
        private final String _fieldName;

        _Fields(short thriftId, String fieldName) {
            _thriftId = thriftId;
            _fieldName = fieldName;
        }

        public short getThriftFieldId() {
            return _thriftId;
        }

        public String getFieldName() {
            return _fieldName;
        }
    }

    // isset id assignments

    public static final Map<_Fields, FieldMetaData> metaDataMap;

    static {
        Map<_Fields, FieldMetaData> tmpMap = new EnumMap<_Fields, FieldMetaData>(_Fields.class);
        tmpMap.put(_Fields.STATUS, new FieldMetaData("status", TFieldRequirementType.REQUIRED,
                new EnumMetaData(TType.ENUM, Status.class)));
        tmpMap.put(_Fields.HEADERS, new FieldMetaData("headers", TFieldRequirementType.OPTIONAL,
                new MapMetaData(TType.MAP,
                        new FieldValueMetaData(TType.STRING),
                        new FieldValueMetaData(TType.STRING))));
        tmpMap.put(_Fields.BODY, new FieldMetaData("body", TFieldRequirementType.OPTIONAL,
                new FieldValueMetaData(TType.STRING)));
        metaDataMap = Collections.unmodifiableMap(tmpMap);
        FieldMetaData.addStructMetaDataMap(RestResponse.class, metaDataMap);
    }

    public RestResponse() {
    }

    public RestResponse(
            Status status) {
        this();
        this.status = status;
    }

    /**
     * Performs a deep copy on <i>other</i>.
     */
    public RestResponse(RestResponse other) {
        if (other.isSetStatus()) {
            this.status = other.status;
        }
        if (other.isSetHeaders()) {
            Map<String, String> __this__headers = new HashMap<String, String>();
            for (Map.Entry<String, String> other_element : other.headers.entrySet()) {

                String other_element_key = other_element.getKey();
                String other_element_value = other_element.getValue();

                String __this__headers_copy_key = other_element_key;

                String __this__headers_copy_value = other_element_value;

                __this__headers.put(__this__headers_copy_key, __this__headers_copy_value);
            }
            this.headers = __this__headers;
        }
        if (other.isSetBody()) {
            this.body = ByteBuffer.wrap(new byte[other.body.limit() - other.body.arrayOffset()]);
            System.arraycopy(other.body.array(), other.body.arrayOffset(), body.array(), 0, other.body.limit() - other.body.arrayOffset());
        }
    }

    public RestResponse deepCopy() {
        return new RestResponse(this);
    }

    @Deprecated
    public RestResponse clone() {
        return new RestResponse(this);
    }

    @Override
    public void clear() {
        this.status = null;
        this.headers = null;
        this.body = null;
    }

    /**
     * @see org.elasticsearch.thrift.Status
     */
    public Status getStatus() {
        return this.status;
    }

    /**
     * @see org.elasticsearch.thrift.Status
     */
    public RestResponse setStatus(Status status) {
        this.status = status;
        return this;
    }

    public void unsetStatus() {
        this.status = null;
    }

    /**
     * Returns true if field status is set (has been asigned a value) and false otherwise
     */
    public boolean isSetStatus() {
        return this.status != null;
    }

    public void setStatusIsSet(boolean value) {
        if (!value) {
            this.status = null;
        }
    }

    public int getHeadersSize() {
        return (this.headers == null) ? 0 : this.headers.size();
    }

    public void putToHeaders(String key, String val) {
        if (this.headers == null) {
            this.headers = new HashMap<String, String>();
        }
        this.headers.put(key, val);
    }

    public Map<String, String> getHeaders() {
        return this.headers;
    }

    public RestResponse setHeaders(Map<String, String> headers) {
        this.headers = headers;
        return this;
    }

    public void unsetHeaders() {
        this.headers = null;
    }

    /**
     * Returns true if field headers is set (has been asigned a value) and false otherwise
     */
    public boolean isSetHeaders() {
        return this.headers != null;
    }

    public void setHeadersIsSet(boolean value) {
        if (!value) {
            this.headers = null;
        }
    }

    public ByteBuffer getBody() {
        return this.body;
    }

    public RestResponse setBody(ByteBuffer body) {
        this.body = body;
        return this;
    }

    public void unsetBody() {
        this.body = null;
    }

    /**
     * Returns true if field body is set (has been asigned a value) and false otherwise
     */
    public boolean isSetBody() {
        return this.body != null;
    }

    public void setBodyIsSet(boolean value) {
        if (!value) {
            this.body = null;
        }
    }

    public void setFieldValue(_Fields field, Object value) {
        switch (field) {
            case STATUS:
                if (value == null) {
                    unsetStatus();
                } else {
                    setStatus((Status) value);
                }
                break;

            case HEADERS:
                if (value == null) {
                    unsetHeaders();
                } else {
                    setHeaders((Map<String, String>) value);
                }
                break;

            case BODY:
                if (value == null) {
                    unsetBody();
                } else {
                    setBody((ByteBuffer) value);
                }
                break;

        }
    }

    public void setFieldValue(int fieldID, Object value) {
        setFieldValue(_Fields.findByThriftIdOrThrow(fieldID), value);
    }

    public Object getFieldValue(_Fields field) {
        switch (field) {
            case STATUS:
                return getStatus();

            case HEADERS:
                return getHeaders();

            case BODY:
                return getBody();

        }
        throw new IllegalStateException();
    }

    public Object getFieldValue(int fieldId) {
        return getFieldValue(_Fields.findByThriftIdOrThrow(fieldId));
    }

    /**
     * Returns true if field corresponding to fieldID is set (has been asigned a value) and false otherwise
     */
    public boolean isSet(_Fields field) {
        switch (field) {
            case STATUS:
                return isSetStatus();
            case HEADERS:
                return isSetHeaders();
            case BODY:
                return isSetBody();
        }
        throw new IllegalStateException();
    }

    public boolean isSet(int fieldID) {
        return isSet(_Fields.findByThriftIdOrThrow(fieldID));
    }

    @Override
    public boolean equals(Object that) {
        if (that == null)
            return false;
        if (that instanceof RestResponse)
            return this.equals((RestResponse) that);
        return false;
    }

    public boolean equals(RestResponse that) {
        if (that == null)
            return false;

        boolean this_present_status = true && this.isSetStatus();
        boolean that_present_status = true && that.isSetStatus();
        if (this_present_status || that_present_status) {
            if (!(this_present_status && that_present_status))
                return false;
            if (!this.status.equals(that.status))
                return false;
        }

        boolean this_present_headers = true && this.isSetHeaders();
        boolean that_present_headers = true && that.isSetHeaders();
        if (this_present_headers || that_present_headers) {
            if (!(this_present_headers && that_present_headers))
                return false;
            if (!this.headers.equals(that.headers))
                return false;
        }

        boolean this_present_body = true && this.isSetBody();
        boolean that_present_body = true && that.isSetBody();
        if (this_present_body || that_present_body) {
            if (!(this_present_body && that_present_body))
                return false;
            if (!this.body.equals(that.body))
                return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return 0;
    }

    public int compareTo(RestResponse other) {
        if (!getClass().equals(other.getClass())) {
            return getClass().getName().compareTo(other.getClass().getName());
        }

        int lastComparison = 0;
        RestResponse typedOther = (RestResponse) other;

        lastComparison = Boolean.valueOf(isSetStatus()).compareTo(typedOther.isSetStatus());
        if (lastComparison != 0) {
            return lastComparison;
        }
        if (isSetStatus()) {
            lastComparison = TBaseHelper.compareTo(this.status, typedOther.status);
            if (lastComparison != 0) {
                return lastComparison;
            }
        }
        lastComparison = Boolean.valueOf(isSetHeaders()).compareTo(typedOther.isSetHeaders());
        if (lastComparison != 0) {
            return lastComparison;
        }
        if (isSetHeaders()) {
            lastComparison = TBaseHelper.compareTo(this.headers, typedOther.headers);
            if (lastComparison != 0) {
                return lastComparison;
            }
        }
        lastComparison = Boolean.valueOf(isSetBody()).compareTo(typedOther.isSetBody());
        if (lastComparison != 0) {
            return lastComparison;
        }
        if (isSetBody()) {
            lastComparison = TBaseHelper.compareTo(this.body, typedOther.body);
            if (lastComparison != 0) {
                return lastComparison;
            }
        }
        return 0;
    }

    public void read(TProtocol iprot) throws TException {
        TField field;
        iprot.readStructBegin();
        while (true) {
            field = iprot.readFieldBegin();
            if (field.type == TType.STOP) {
                break;
            }
            switch (field.id) {
                case 1: // STATUS
                    if (field.type == TType.I32) {
                        this.status = Status.findByValue(iprot.readI32());
                    } else {
                        TProtocolUtil.skip(iprot, field.type);
                    }
                    break;
                case 2: // HEADERS
                    if (field.type == TType.MAP) {
                        {
                            TMap _map10 = iprot.readMapBegin();
                            this.headers = new HashMap<String, String>(2 * _map10.size);
                            for (int _i11 = 0; _i11 < _map10.size; ++_i11) {
                                String _key12;
                                String _val13;
                                _key12 = iprot.readString();
                                _val13 = iprot.readString();
                                this.headers.put(_key12, _val13);
                            }
                            iprot.readMapEnd();
                        }
                    } else {
                        TProtocolUtil.skip(iprot, field.type);
                    }
                    break;
                case 3: // BODY
                    if (field.type == TType.STRING) {
                        this.body = iprot.readBinary();
                    } else {
                        TProtocolUtil.skip(iprot, field.type);
                    }
                    break;
                default:
                    TProtocolUtil.skip(iprot, field.type);
            }
            iprot.readFieldEnd();
        }
        iprot.readStructEnd();

        // check for required fields of primitive type, which can't be checked in the validate method
        validate();
    }

    public void write(TProtocol oprot) throws TException {
        validate();

        oprot.writeStructBegin(STRUCT_DESC);
        if (this.status != null) {
            oprot.writeFieldBegin(STATUS_FIELD_DESC);
            oprot.writeI32(this.status.getValue());
            oprot.writeFieldEnd();
        }
        if (this.headers != null) {
            if (isSetHeaders()) {
                oprot.writeFieldBegin(HEADERS_FIELD_DESC);
                {
                    oprot.writeMapBegin(new TMap(TType.STRING, TType.STRING, this.headers.size()));
                    for (Map.Entry<String, String> _iter14 : this.headers.entrySet()) {
                        oprot.writeString(_iter14.getKey());
                        oprot.writeString(_iter14.getValue());
                    }
                    oprot.writeMapEnd();
                }
                oprot.writeFieldEnd();
            }
        }
        if (this.body != null) {
            if (isSetBody()) {
                oprot.writeFieldBegin(BODY_FIELD_DESC);
                oprot.writeBinary(this.body);
                oprot.writeFieldEnd();
            }
        }
        oprot.writeFieldStop();
        oprot.writeStructEnd();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("RestResponse(");
        boolean first = true;

        sb.append("status:");
        if (this.status == null) {
            sb.append("null");
        } else {
            sb.append(this.status);
        }
        first = false;
        if (isSetHeaders()) {
            if (!first) sb.append(", ");
            sb.append("headers:");
            if (this.headers == null) {
                sb.append("null");
            } else {
                sb.append(this.headers);
            }
            first = false;
        }
        if (isSetBody()) {
            if (!first) sb.append(", ");
            sb.append("body:");
            if (this.body == null) {
                sb.append("null");
            } else {
                TBaseHelper.toString(this.body, sb);
            }
            first = false;
        }
        sb.append(")");
        return sb.toString();
    }

    public void validate() throws TException {
        // check for required fields
        if (status == null) {
            throw new TProtocolException("Required field 'status' was not present! Struct: " + toString());
        }
    }

}

