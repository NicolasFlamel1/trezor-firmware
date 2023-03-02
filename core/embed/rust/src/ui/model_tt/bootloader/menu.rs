use crate::ui::{
    component::{Child, Component, Event, EventCtx, Label, Pad},
    constant::{screen, HEIGHT, WIDTH},
    display::Icon,
    geometry::{Alignment, Insets, Point, Rect},
    model_tt::{
        bootloader::theme::{
            button_bld, button_bld_menu, BLD_BG, BUTTON_HEIGHT, CONTENT_PADDING,
            CORNER_BUTTON_AREA, CORNER_BUTTON_TOUCH_EXPANSION, FIRE24, REFRESH24, TEXT_TITLE,
            TITLE_AREA, TITLE_Y_ADJUSTMENT, X32,
        },
        component::{Button, ButtonMsg::Clicked, IconText},
    },
};
use heapless::String;

const BUTTON_AREA_START: i16 = 56;
const BUTTON_SPACING: i16 = 8;

#[repr(u32)]
#[derive(Copy, Clone, ToPrimitive)]
pub enum MenuMsg {
    Close = 1,
    Reboot = 2,
    FactoryReset = 3,
}

pub struct Menu {
    bg: Pad,
    title: Child<Label<String<32>>>,
    close: Child<Button<&'static str>>,
    reboot: Child<Button<&'static str>>,
    reset: Child<Button<&'static str>>,
}

impl Menu {
    pub fn new(_bld_version: &'static str) -> Self {
        let content_reboot = IconText::new("REBOOT TREZOR", Icon::new(REFRESH24));
        let content_reset = IconText::new("FACTORY RESET", Icon::new(FIRE24));

        let mut title: String<32> = String::new();
        unwrap!(title.push_str("BOOTLOADER "));

        let mut instance = Self {
            bg: Pad::with_background(BLD_BG),
            title: Child::new(Label::new(title, Alignment::Start, TEXT_TITLE)),
            close: Child::new(
                Button::with_icon(Icon::new(X32))
                    .styled(button_bld_menu())
                    .with_expanded_touch_area(Insets::uniform(CORNER_BUTTON_TOUCH_EXPANSION)),
            ),
            reboot: Child::new(Button::with_icon_and_text(content_reboot).styled(button_bld())),
            reset: Child::new(Button::with_icon_and_text(content_reset).styled(button_bld())),
        };
        instance.bg.clear();
        instance
    }
}

impl Component for Menu {
    type Msg = MenuMsg;

    fn place(&mut self, bounds: Rect) -> Rect {
        self.bg.place(screen());
        self.title.place(TITLE_AREA);
        let title_height = self.title.inner().area().height();
        self.title.place(Rect::new(
            Point::new(
                CONTENT_PADDING,
                TITLE_AREA.center().y - (title_height / 2) - TITLE_Y_ADJUSTMENT,
            ),
            Point::new(WIDTH - CONTENT_PADDING, HEIGHT),
        ));
        self.close.place(CORNER_BUTTON_AREA);
        self.reboot.place(Rect::new(
            Point::new(CONTENT_PADDING, BUTTON_AREA_START),
            Point::new(WIDTH - CONTENT_PADDING, BUTTON_AREA_START + BUTTON_HEIGHT),
        ));
        self.reset.place(Rect::new(
            Point::new(
                CONTENT_PADDING,
                BUTTON_AREA_START + BUTTON_HEIGHT + BUTTON_SPACING,
            ),
            Point::new(
                WIDTH - CONTENT_PADDING,
                BUTTON_AREA_START + 2 * BUTTON_HEIGHT + BUTTON_SPACING,
            ),
        ));
        bounds
    }

    fn event(&mut self, ctx: &mut EventCtx, event: Event) -> Option<Self::Msg> {
        if let Some(Clicked) = self.close.event(ctx, event) {
            return Some(Self::Msg::Close);
        }
        if let Some(Clicked) = self.reboot.event(ctx, event) {
            return Some(Self::Msg::Reboot);
        }
        if let Some(Clicked) = self.reset.event(ctx, event) {
            return Some(Self::Msg::FactoryReset);
        }

        None
    }

    fn paint(&mut self) {
        self.bg.paint();
        self.title.paint();
        self.close.paint();
        self.reboot.paint();
        self.reset.paint();
    }

    #[cfg(feature = "ui_bounds")]
    fn bounds(&self, sink: &mut dyn FnMut(Rect)) {
        self.close.bounds(sink);
        self.reboot.bounds(sink);
        self.reset.bounds(sink);
    }
}