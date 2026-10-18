// Reduced from #3864's chamilo/chamilo-lms grapes.js bundled-wrapper shape.
// Each factory receives its own module object, not the file's free exports.
var modules = [
  function(module, exports, require) {
    exports.default = function() {
      return { getStyle: function() { return 'first'; } };
    };
    exports.default().getStyle();
  },
  function(module, exports, require) {
    exports.default = function() {
      return { getStyle: function() { return 'second'; } };
    };
    exports.default().getStyle();
  }
];
