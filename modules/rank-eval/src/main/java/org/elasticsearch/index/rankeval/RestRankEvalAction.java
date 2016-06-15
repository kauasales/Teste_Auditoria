/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.index.rankeval;

import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;

/**
 * Accepted input format:
 * 
 * General Format:
 * 
 * 
  { "requests": [{
        "id": "human_readable_id",
        "request": { ... request to check ... },
        "ratings": { ... mapping from doc id to rating value ... }
     }],
    "evaluation_metric": {
        "... metric_name... ": {
            "... metric_parameter_key ...": ...metric_parameter_value...
        }}}
 * 
 * Example: 
 * 
 * 
   {"requests": [{
        "id": "amsterdam_query",
        "request": {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"beverage": "coffee"}}, 
                            {"term": {"browser": {"value": "safari"}}},
                            {"term": {"time_of_day": {"value": "morning","boost": 2}}},
                            {"term": {"ip_location": {"value": "ams","boost": 10}}}]}
                },
                "size": 10
            }
        },
        "doc_ratings": {
            "1": 1,
            "2": 0,
            "3": 1,
            "4": 1
        }
    }, {
        "id": "berlin_query",
        "request": {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"beverage": "club mate"}}, 
                            {"term": {"browser": {"value": "chromium"}}},
                            {"term": {"time_of_day": {"value": "evening","boost": 2}}},
                            {"term": {"ip_location": {"value": "ber","boost": 10}}}]}
                },
                "size": 10
            }
        },
        "doc_ratings": {
            "1": 0,
            "5": 1,
            "6": 1
        }
    }],
    "evaluation_metric": {
        "precisionAtN": {
            "size": 10}}
  } 
 
 * 
 * Output format:
 * 
 * General format:
 * 
 * 
 {
    "took": 59,
    "timed_out": false,
    "_shards": {
        "total": 5,
        "successful": 5,
        "failed": 0
    },
    "rank_eval": [{
        "spec_id": "... id_of_query_template_specification ...",
        "quality_level": ... quality level ...,
        "unknown_docs": [{
            "user_request_id": [... list of unknown docs ...]
        }]
    }]
} 

 * 
 * Example:
 * 
 * 
 * 
  {
    "took": 59,
    "timed_out": false,
    "_shards": {
        "total": 5,
        "successful": 5,
        "failed": 0
    },
    "rank_eval": [{
        "spec_id": "huge_weight_on_city",
        "quality_level": 0.4,
        "unknown_docs": [{
            "amsterdam_query": [5, 10, 23]
        }, {
            "berlin_query": [42]
        }]
    }]
  }
  
  
 * */
public class RestRankEvalAction extends BaseRestHandler {

    protected RestRankEvalAction(Settings settings, Client client) {
        super(settings, client);
    }

    @Override
    protected void handleRequest(RestRequest request, RestChannel channel, Client client) throws Exception {
    }

}
