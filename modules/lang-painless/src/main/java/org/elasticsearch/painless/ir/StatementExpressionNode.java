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

package org.elasticsearch.painless.ir;

import org.elasticsearch.painless.ClassWriter;
import org.elasticsearch.painless.Globals;
import org.elasticsearch.painless.MethodWriter;
import org.elasticsearch.painless.symbol.ScopeTable;

public class StatementExpressionNode extends StatementNode {

    /* ---- begin tree structure ---- */

    private ExpressionNode expressionNode;

    public void setExpressionNode(ExpressionNode expressionNode) {
        this.expressionNode = expressionNode;
    }

    public ExpressionNode getExpressionNode() {
        return expressionNode;
    }

    /* ---- end tree structure, begin node data ---- */

    private boolean methodEscape;
    private boolean doNoop;

    public void setMethodEscape(boolean methodEscape) {
        this.methodEscape = methodEscape;
    }

    public boolean getMethodEscape() {
        return methodEscape;
    }

    public void setNoop(boolean doNoop) {
        this.doNoop = doNoop;
    }

    public boolean doNoop() {
        return doNoop;
    }

    /* ---- end node data ---- */

    @Override
    protected void write(ClassWriter classWriter, MethodWriter methodWriter, Globals globals, ScopeTable scopeTable) {
        methodWriter.writeStatementOffset(location);
        expressionNode.write(classWriter, methodWriter, globals, scopeTable);

        if (doNoop == false) {
            if (methodEscape) {
                methodWriter.returnValue();
            } else {
                methodWriter.writePop(MethodWriter.getType(expressionNode.getExpressionType()).getSize());
            }
        }
    }
}
