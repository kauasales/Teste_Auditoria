/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.ingest.geoip;

import com.maxmind.db.Network;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.AbstractResponse;
import com.maxmind.geoip2.model.AnonymousIpResponse;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.ConnectionTypeResponse;
import com.maxmind.geoip2.model.CountryResponse;
import com.maxmind.geoip2.model.DomainResponse;
import com.maxmind.geoip2.model.EnterpriseResponse;
import com.maxmind.geoip2.model.IpRiskResponse;
import com.maxmind.geoip2.model.IspResponse;
import com.maxmind.geoip2.record.MaxMind;

import org.elasticsearch.test.ESTestCase;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.equalTo;

public class MaxMindSupportTests extends ESTestCase {

    private static final Set<String> ASN_SUPPORTED_FIELDS = Set.of("autonomousSystemNumber", "autonomousSystemOrganization", "network");
    private static final Set<String> ASN_UNSUPPORTED_FIELDS = Set.of("ipAddress");

    private static final Set<String> CITY_SUPPORTED_FIELDS = Set.of(
        "city.name",
        "continent.name",
        "country.isoCode",
        "country.name",
        "location.latitude",
        "location.longitude",
        "location.timeZone",
        "mostSpecificSubdivision.isoCode",
        "mostSpecificSubdivision.name"
    );
    private static final Set<String> CITY_UNSUPPORTED_FIELDS = Set.of(
        "city.confidence",
        "city.geoNameId",
        "city.names",
        "continent.code",
        "continent.geoNameId",
        "continent.names",
        "country.confidence",
        "country.geoNameId",
        "country.inEuropeanUnion",
        "country.names",
        "leastSpecificSubdivision.confidence",
        "leastSpecificSubdivision.geoNameId",
        "leastSpecificSubdivision.isoCode",
        "leastSpecificSubdivision.name",
        "leastSpecificSubdivision.names",
        "location.accuracyRadius",
        "location.averageIncome",
        "location.metroCode",
        "location.populationDensity",
        "maxMind",
        "mostSpecificSubdivision.confidence",
        "mostSpecificSubdivision.geoNameId",
        "mostSpecificSubdivision.names",
        "postal.code",
        "postal.confidence",
        "registeredCountry.confidence",
        "registeredCountry.geoNameId",
        "registeredCountry.inEuropeanUnion",
        "registeredCountry.isoCode",
        "registeredCountry.name",
        "registeredCountry.names",
        "representedCountry.confidence",
        "representedCountry.geoNameId",
        "representedCountry.inEuropeanUnion",
        "representedCountry.isoCode",
        "representedCountry.name",
        "representedCountry.names",
        "representedCountry.type",
        "subdivisions.confidence",
        "subdivisions.geoNameId",
        "subdivisions.isoCode",
        "subdivisions.name",
        "subdivisions.names",
        "traits.anonymous",
        "traits.anonymousProxy",
        "traits.anonymousVpn",
        "traits.anycast",
        "traits.autonomousSystemNumber",
        "traits.autonomousSystemOrganization",
        "traits.connectionType",
        "traits.domain",
        "traits.hostingProvider",
        "traits.ipAddress",
        "traits.isp",
        "traits.legitimateProxy",
        "traits.mobileCountryCode",
        "traits.mobileNetworkCode",
        "traits.network",
        "traits.organization",
        "traits.publicProxy",
        "traits.residentialProxy",
        "traits.satelliteProvider",
        "traits.staticIpScore",
        "traits.torExitNode",
        "traits.userCount",
        "traits.userType"
    );

    private static final Set<String> COUNTRY_SUPPORTED_FIELDS = Set.of("continent.name", "country.isoCode", "country.name");
    private static final Set<String> COUNTRY_UNSUPPORTED_FIELDS = Set.of(
        "continent.code",
        "continent.geoNameId",
        "continent.names",
        "country.confidence",
        "country.geoNameId",
        "country.inEuropeanUnion",
        "country.names",
        "maxMind",
        "registeredCountry.confidence",
        "registeredCountry.geoNameId",
        "registeredCountry.inEuropeanUnion",
        "registeredCountry.isoCode",
        "registeredCountry.name",
        "registeredCountry.names",
        "representedCountry.confidence",
        "representedCountry.geoNameId",
        "representedCountry.inEuropeanUnion",
        "representedCountry.isoCode",
        "representedCountry.name",
        "representedCountry.names",
        "representedCountry.type",
        "traits.anonymous",
        "traits.anonymousProxy",
        "traits.anonymousVpn",
        "traits.anycast",
        "traits.autonomousSystemNumber",
        "traits.autonomousSystemOrganization",
        "traits.connectionType",
        "traits.domain",
        "traits.hostingProvider",
        "traits.ipAddress",
        "traits.isp",
        "traits.legitimateProxy",
        "traits.mobileCountryCode",
        "traits.mobileNetworkCode",
        "traits.network",
        "traits.organization",
        "traits.publicProxy",
        "traits.residentialProxy",
        "traits.satelliteProvider",
        "traits.staticIpScore",
        "traits.torExitNode",
        "traits.userCount",
        "traits.userType"
    );

    private static final Map<Database, Set<String>> TYPE_TO_SUPPORTED_FIELDS_MAP = Map.of(
        Database.Asn,
        ASN_SUPPORTED_FIELDS,
        Database.City,
        CITY_SUPPORTED_FIELDS,
        Database.Country,
        COUNTRY_SUPPORTED_FIELDS
    );
    private static final Map<Database, Set<String>> TYPE_TO_UNSUPPORTED_FIELDS_MAP = Map.of(
        Database.Asn,
        ASN_UNSUPPORTED_FIELDS,
        Database.City,
        CITY_UNSUPPORTED_FIELDS,
        Database.Country,
        COUNTRY_UNSUPPORTED_FIELDS
    );
    private static final Map<Database, Class<? extends AbstractResponse>> TYPE_TO_MAX_MIND_CLASS = Map.of(
        Database.Asn,
        AsnResponse.class,
        Database.City,
        CityResponse.class,
        Database.Country,
        CountryResponse.class
    );

    private static final Set<Class<? extends AbstractResponse>> KNOWN_UNSUPPORTED_RESPONSE_CLASSES = Set.of(
        AnonymousIpResponse.class,
        ConnectionTypeResponse.class,
        DomainResponse.class,
        EnterpriseResponse.class,
        IspResponse.class,
        IpRiskResponse.class
    );

    public void testMaxMindSupport() {
        for (Database databaseType : Database.values()) {
            Class<? extends AbstractResponse> maxMindClass = TYPE_TO_MAX_MIND_CLASS.get(databaseType);
            Set<String> supportedFields = TYPE_TO_SUPPORTED_FIELDS_MAP.get(databaseType);
            Set<String> unsupportedFields = TYPE_TO_UNSUPPORTED_FIELDS_MAP.get(databaseType);
            assertNotNull(
                "A new Database type, "
                    + databaseType
                    + ", has been added, but this test has not been updated to know which MaxMind "
                    + "class to use to load it. Update TYPE_TO_MAX_MIND_CLASS",
                maxMindClass
            );
            assertNotNull(
                "A new Database type, "
                    + databaseType
                    + ", has been added, but this test has not been updated to know which fields we "
                    + "support for it. Update TYPE_TO_SUPPORTED_FIELDS_MAP",
                supportedFields
            );
            assertNotNull(
                "A new Database type, "
                    + databaseType
                    + ", has been added, but this test has not been updated to know which fields we "
                    + "do not support for it. Update TYPE_TO_UNSUPPORTED_FIELDS_MAP",
                unsupportedFields
            );
            final SortedSet<String> fieldNames = getFieldNamesUsedFromClass(maxMindClass);
            SortedSet<String> unusedFields = new TreeSet<>(fieldNames);
            unusedFields.removeAll(supportedFields);
            assertThat(
                "New MaxMind fields have been added for "
                    + databaseType
                    + " that we do not use or have documented in TYPE_TO_UNSUPPORTED_FIELDS_MAP. The actual list of fields is:\n"
                    + getFormattedList(unusedFields),
                unusedFields,
                equalTo(new TreeSet<>(unsupportedFields))
            );
            SortedSet<String> nonexistentFields = new TreeSet<>(supportedFields);
            nonexistentFields.removeAll(fieldNames);
            assertThat(
                "We are attempting to use fields that MaxMind does not support for " + databaseType,
                nonexistentFields.size(),
                equalTo(0)
            );
        }
    }

    public void testUnknownMaxMindResponseClassess() {
        Set<Class<? extends AbstractResponse>> supportedMaxMindClasses = new HashSet<>(TYPE_TO_MAX_MIND_CLASS.values());
        // First just a sanity check that there's no overlap between what's supported and what's not:
        Set<Class<? extends AbstractResponse>> supportedAndUnsupportedMaxMindClasses = new HashSet<>(supportedMaxMindClasses);
        supportedAndUnsupportedMaxMindClasses.retainAll(KNOWN_UNSUPPORTED_RESPONSE_CLASSES);
        assertThat(
            "We claim both to support and not support some MaxMind response classes: " + supportedAndUnsupportedMaxMindClasses,
            supportedAndUnsupportedMaxMindClasses,
            equalTo(Set.of())
        );
        Set<Class<? extends AbstractResponse>> allActualMaxMindClasses = new HashSet<>();

        Method[] methods = DatabaseReader.class.getMethods();
        for (Method method : methods) {
            if (method.getName().startsWith("try")) {
                if (method.getReturnType().equals(Optional.class)) {
                    Type genericReturnType = method.getGenericReturnType();
                    if (genericReturnType instanceof ParameterizedType parameterizedGenericReturnType) {
                        Type[] actualTypes = parameterizedGenericReturnType.getActualTypeArguments();
                        if (actualTypes != null && actualTypes.length == 1 && actualTypes[0] instanceof Class<?> actualTypeClass) {
                            allActualMaxMindClasses.add(actualTypeClass.asSubclass(AbstractResponse.class));
                            if (KNOWN_UNSUPPORTED_RESPONSE_CLASSES.contains(actualTypeClass) == false) {
                                assertTrue(
                                    "MaxMind has added support for " + actualTypeClass.getSimpleName(),
                                    supportedMaxMindClasses.contains(actualTypeClass)
                                );
                            }
                        }
                    }
                }
            }
        }
        // Now make sure that we're not claiming to support any maxmind classes that aren't ever read by DatabaseReader:
        Set<Class<? extends AbstractResponse>> supportedMaxMindClassesThatDoNotExist = new HashSet<>(supportedMaxMindClasses);
        supportedMaxMindClassesThatDoNotExist.removeAll(allActualMaxMindClasses);
        assertThat(
            "We claim both to support a MaxMind response class that MaxMind does not expose through DatabaseReader: "
                + supportedMaxMindClassesThatDoNotExist,
            supportedMaxMindClassesThatDoNotExist,
            equalTo(Set.of())
        );
    }

    /*
     * This tests that this test has a mapping in TYPE_TO_MAX_MIND_CLASS for all MaxMind classes exposed through GeoIpDatabase.
     */
    public void testUsedMaxMindResponseClassesAreAccountedFor() {
        Set<Class<? extends AbstractResponse>> usedMaxMindResponseClasses = getUsedMaxMindResponseClasses();
        Set<Class<? extends AbstractResponse>> supportedMaxMindClasses = new HashSet<>(TYPE_TO_MAX_MIND_CLASS.values());
        Set<Class<? extends AbstractResponse>> usedButNotSupportedMaxMindResponseClasses = new HashSet<>(usedMaxMindResponseClasses);
        usedButNotSupportedMaxMindResponseClasses.removeAll(supportedMaxMindClasses);
        assertThat(
            "GeoIpDatabase exposes MaxMind response classes that this test does not know what to do with. Add mappings to "
                + "TYPE_TO_MAX_MIND_CLASS for the following: "
                + usedButNotSupportedMaxMindResponseClasses,
            usedButNotSupportedMaxMindResponseClasses,
            equalTo(Set.of())
        );
        Set<Class<? extends AbstractResponse>> supportedButNotUsedMaxMindClasses = new HashSet<>(supportedMaxMindClasses);
        supportedButNotUsedMaxMindClasses.removeAll(usedMaxMindResponseClasses);
        assertThat(
            "This test claims to support MaxMind response classes that are not exposed in GeoIpDatabase. Remove the following from "
                + "TYPE_TO_MAX_MIND_CLASS: "
                + supportedButNotUsedMaxMindClasses,
            supportedButNotUsedMaxMindClasses,
            equalTo(Set.of())
        );
    }

    /*
     * This is the list of field types that causes us to stop recursing. That is, fields of these types are the lowest-level fields that
     * we care about.
     */
    private static final Set<Class<?>> TERMINAL_TYPES = Set.of(
        boolean.class,
        Boolean.class,
        char.class,
        Character.class,
        Class.class,
        ConnectionTypeResponse.ConnectionType.class,
        double.class,
        Double.class,
        InetAddress.class,
        int.class,
        Integer.class,
        long.class,
        Long.class,
        MaxMind.class,
        Network.class,
        Object.class,
        String.class,
        void.class,
        Void.class
    );
    /*
     * These are types that are containers for other types. We don't need to recurse into each method on these types. Instead, we need to
     *  look at their generic types.
     */
    private static final Set<Class<?>> CONTAINER_TYPES = Set.of(Collection.class, List.class, Map.class, Optional.class);
    /*
     * These are methods we don't want to traverse into.
     */
    private static final Set<Method> IGNORED_METHODS = Arrays.stream(Object.class.getMethods()).collect(Collectors.toUnmodifiableSet());

    /*
     * Returns the set of bean-property-like field names referenced from aClass, sorted alphabetically.
     */
    private static SortedSet<String> getFieldNamesUsedFromClass(Class<?> aClass) {
        SortedSet<String> fieldNames = new TreeSet<>();
        getFieldNamesUsedFromClass(fieldNames, "", aClass);
        return fieldNames;
    }

    private static void getFieldNamesUsedFromClass(Set<String> fieldsSet, String context, Class<?> aClass) {
        Method[] methods = aClass.getMethods();
        if (TERMINAL_TYPES.contains(aClass)) {
            // We got here becaus a collection type had a terminal type
            fieldsSet.add(context);
            return;
        }
        for (Method method : methods) {
            if (IGNORED_METHODS.contains(method)) {
                continue;
            }
            if (method.getName().startsWith("to")) {
                // ignoring methods like toJson or toString
                continue;
            }
            String currentContext = context + (context.isEmpty() ? "" : ".") + beanify(method.getName());
            if (TERMINAL_TYPES.contains(method.getReturnType())) {
                fieldsSet.add(currentContext);
            } else {
                Class<?> returnType = method.getReturnType();
                if (CONTAINER_TYPES.contains(returnType)) {
                    ParameterizedType genericReturnType = (ParameterizedType) method.getGenericReturnType();
                    for (Type actualType : genericReturnType.getActualTypeArguments()) {
                        if (actualType instanceof Class<?> actualTypeClass) {
                            getFieldNamesUsedFromClass(fieldsSet, currentContext, actualTypeClass);
                        } else {
                            assert false : "This test needs to be updated to deal with this situation";
                        }
                    }
                } else {
                    getFieldNamesUsedFromClass(fieldsSet, currentContext, method.getReturnType());
                }
            }
        }
    }

    /*
     * This method converts a method name into what would be its equivalent bean property. For example "getName" returns "name".
     */
    private static String beanify(String methodName) {
        if (methodName.startsWith("get")) {
            return beanify("get", methodName);
        } else if (methodName.startsWith("is")) {
            return beanify("is", methodName);
        } else {
            return methodName;
        }
    }

    private static String beanify(String prefix, String methodName) {
        return methodName.substring(prefix.length(), prefix.length() + 1).toLowerCase(Locale.ROOT) + methodName.substring(
            prefix.length() + 1
        );
    }

    /*
     * This is a convenience to format the list of field names in fields into a String that can be copied into a Set initializer above,
     * like countryUnsupportedFields.
     */
    private static String getFormattedList(Set<String> fields) {
        StringBuilder result = new StringBuilder();
        for (Iterator<String> it = fields.iterator(); it.hasNext();) {
            result.append("\"");
            result.append(it.next());
            result.append("\"");
            if (it.hasNext()) {
                result.append(",\n");
            }
        }
        return result.toString();
    }

    /*
     * This returns all AbstractResponse classes that are returned from getter methods on GeoIpDatabase.
     */
    private static Set<Class<? extends AbstractResponse>> getUsedMaxMindResponseClasses() {
        Set<Class<? extends AbstractResponse>> result = new HashSet<>();
        Method[] methods = GeoIpDatabase.class.getMethods();
        for (Method method : methods) {
            if (method.getName().startsWith("get")) {
                Class<?> returnType = method.getReturnType();
                try {
                    result.add(returnType.asSubclass(AbstractResponse.class));
                } catch (ClassCastException ignore) {
                    // This is not what we were looking for, move on
                }
            }
        }
        return result;
    }
}
