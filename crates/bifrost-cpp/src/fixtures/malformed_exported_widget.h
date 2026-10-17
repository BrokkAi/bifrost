#define VIEWS_EXPORT
namespace internal { class NativeWidgetDelegate {}; }
namespace ui {
class EventSource {};
class NativeThemeObserver {};
class ColorProviderSource {};
class PropertyHandler {};
class AXModeObserver {};
namespace metadata { class MetaDataProvider {}; }
}
class FocusTraversable {};
namespace views {
class VIEWS_EXPORT Widget : public internal::NativeWidgetDelegate,
                            public ui::EventSource,
                            public FocusTraversable,
                            public ui::NativeThemeObserver,
                            public ui::ColorProviderSource,
                            public ui::PropertyHandler,
                            public ui::AXModeObserver,
                            public ui::metadata::MetaDataProvider {
    ADVANCED_MEMORY_SAFETY_CHECKS();

 public:
    Widget();
};
}

class Outer { class Nested; };
class API {};
class API *pointer_value;
class API &reference_value = *pointer_value;
class API array_value[1];
class API object_value{};
