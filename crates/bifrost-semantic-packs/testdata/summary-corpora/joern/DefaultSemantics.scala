// Test slice of Joern's default flow semantics.
//
// Upstream: https://github.com/joernio/joern
//   path:     dataflowengineoss/src/main/scala/io/joern/dataflowengineoss/DefaultSemantics.scala
//   revision: 8a73ec09be8fa59dba3cfed5959690c003d7ca52
//   license:  Apache-2.0 (see LICENSE in the upstream repository)
//
// The `javaFlows` list below is copied verbatim from the pinned upstream file,
// with one added `F` entry that carries an empty mapping list so the no-flow
// claim has coverage. The slice exists so reader tests never touch the network
// and never vendor the whole corpus; scripts/public/fetch-pinned-summary-corpora.sh
// fetches the pinned file for a foundry run.
package io.joern.dataflowengineoss

object DefaultSemanticsSlice {

  /** Semantic summaries for common external Java calls.
    */
  def javaFlows: List[FlowSemantic] = List(
    PTF("java.lang.String.split:java.lang.String[](java.lang.String)", List((0, 0))),
    PTF("java.lang.String.split:java.lang.String[](java.lang.String,int)", List((0, 0))),
    PTF("java.lang.String.compareTo:int(java.lang.String)", List((0, 0))),
    F("java.io.PrintWriter.print:void(java.lang.String)", List((0, 0), (1, 1))),
    F("java.io.PrintWriter.println:void(java.lang.String)", List((0, 0), (1, 1))),
    F("java.io.PrintStream.println:void(java.lang.String)", List((0, 0), (1, 1))),
    PTF("java.io.PrintStream.print:void(java.lang.String)", List((0, 0))),
    F("android.text.TextUtils.isEmpty:boolean(java.lang.String)", List((0, -1), (1, -1))),
    F("java.sql.PreparedStatement.prepareStatement:java.sql.PreparedStatement(java.lang.String)", List((1, -1))),
    F("java.sql.PreparedStatement.prepareStatement:setDouble(int,double)", List((1, 1), (2, 2))),
    F("java.sql.PreparedStatement.prepareStatement:setFloat(int,float)", List((1, 1), (2, 2))),
    F("java.sql.PreparedStatement.prepareStatement:setInt(int,int)", List((1, 1), (2, 2))),
    F("java.sql.PreparedStatement.prepareStatement:setLong(int,long)", List((1, 1), (2, 2))),
    F("java.sql.PreparedStatement.prepareStatement:setShort(int,short)", List((1, 1), (2, 2))),
    F("java.sql.PreparedStatement.prepareStatement:setString(int,java.lang.String)", List((1, 1), (2, 2))),
    F("org.apache.http.HttpRequest.<init>:void(org.apache.http.RequestLine)", List((1, 1), (1, 0))),
    F("org.apache.http.HttpRequest.<init>:void(java.lang.String,java.lang.String)", List((1, 1), (1, 0), (2, 0))),
    F(
      "org.apache.http.HttpRequest.<init>:void(java.lang.String,java.lang.String,org.apache.http.ProtocolVersion)",
      List((1, 1), (1, 0), (2, 2), (2, 0), (3, 3), (3, 0))
    ),
    F("org.apache.http.HttpResponse.getStatusLine:org.apache.http.StatusLine()", List((0, -1))),
    F("org.apache.http.HttpResponse.setStatusLine:void(org.apache.http.StatusLine)", List((1, 0), (1, 1), (0, -1))),
    F("org.apache.http.HttpResponse.setReasonPhrase:void(java.lang.String)", List((1, 0), (1, 1), (0, -1))),
    F("org.apache.http.HttpResponse.getEntity:org.apache.http.HttpEntity()", List((0, -1))),
    F("org.apache.http.HttpResponse.setEntity:void(org.apache.http.HttpEntity)", List((1, 0), (1, 1), (1, 0))),
    F("java.lang.String.length:int()", List.empty[(Int, Int)])
  )

}
