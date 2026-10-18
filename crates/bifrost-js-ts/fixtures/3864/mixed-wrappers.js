// Object and function exports in separate bundled modules must not share children.
var modules = [
  function(module, exports) {
    exports.default = { getStyle: function() { return 'object'; } };
  },
  function(module, exports) {
    exports.default = function() {
      return { getStyle: function() { return 'first function'; } };
    };
  },
  function(module, exports) {
    exports.default = function() {
      return { getStyle: function() { return 'second function'; } };
    };
  }
];
