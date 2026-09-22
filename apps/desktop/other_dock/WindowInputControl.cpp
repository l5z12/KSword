#include "WindowInputControl.h"
#include "DwmZOrderControl.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QThread>
#include <QVBoxLayout>
#include <iterator>
#include <memory>
#include <vector>

namespace ks::window_input
{
    namespace
    {
        QWidget* createAgentPanel(QWidget* parent);
        QString localizedText(const char* source)
        { return ks::i18n::sourceText(QString::fromUtf8(source)); }

        void bindLabelText(QObject* object, const char* source)
        {
            const auto kValue = QString::fromUtf8(source);
            ks::i18n::LanguageManager::instance().bindText(object, kValue, kValue);
        }

        std::wstring agentPath()
        {
            return QDir::toNativeSeparators(QCoreApplication::applicationDirPath()
                + QStringLiteral("/KswordDwmZOrder.dll")).toStdWString();
        }

        QLabel* label(QWidget* parent, const char* source, QVBoxLayout* layout, bool bind = true)
        {
            auto* label = new QLabel(parent);
            label->setWordWrap(true);
            label->setTextFormat(Qt::PlainText);
            label->setTextInteractionFlags(Qt::TextSelectableByMouse);
            if (bind) bindLabelText(label, source);
            else label->setText(localizedText(source));
            layout->addWidget(label);
            return label;
        }

        QString failure(const Result& result)
        {
            QString message;
            switch (result.status)
            {
            case Status::kInvalidWindow: message = localizedText("目标窗口已关闭或身份发生变化，请重新选择。"); break;
            case Status::kSelfWindow: message = localizedText("不能对 KSword 自身设置输入限制，请选择其他程序的窗口。"); break;
            case Status::kUnsupportedWindow: message = localizedText("该窗口不支持所选模式。穿透不能用于自有 DC 类；遮挡点击要求可见、已启用、未最小化且无所有者的顶层窗口。"); break;
            case Status::kOrderInUse: message = localizedText("已有窗口正在保持 DWM 顺序。请先恢复该窗口，再启用遮挡点击。"); break;
            case Status::kOrderChanged: message = localizedText("原生置顶或 DWM 保持已改变，请恢复后重新应用。"); break;
            case Status::kLimitReached: message = localizedText("已达到 128 个受控窗口，请先恢复部分窗口。"); break;
            case Status::kRestoreFailed: message = localizedText("未能完整恢复，仍保留恢复记录。请检查权限后重试。"); break;
            case Status::kDwmFailure: message = localizedText("DWM 操作未完成，未确认遮挡点击模式已启用。"); break;
            case Status::kKernelFailure:
                if (result.kernelStatus == static_cast<std::int32_t>(0xC0000059))
                    message = localizedText("系统版本或窗口状态不匹配。请重新读取；当前 Win32k 顺序控制仅适配 26100.9022。");
                else if (result.kernelStatus == static_cast<std::int32_t>(0xC00000BB))
                    message = localizedText("该窗口不支持跨 Band 调整。请选择同一桌面中、没有所有者或附属弹窗的普通顶层窗口。");
                else message = localizedText("Win32k 未确认顺序调整成功。请检查管理员权限，并使用配套的新版本 R0 驱动。");
                break;
            default: message = localizedText("Windows 未确认输入设置生效，请检查权限和窗口状态。"); break;
            }
            if (result.dwmAttempted && (result.status == Status::kDwmFailure || result.status == Status::kRestoreFailed))
            {
                if (result.dwm.response.status == dwm_order::Status::kNotRunning)
                    message += QLatin1Char('\n') + localizedText("请使用本页的“加载 DWM 代理”按钮连接 DWM。");
                else if (result.dwm.response.status != dwm_order::Status::kOk)
                    message += QLatin1Char('\n') + dwm_order::errorDescription(result.dwm);
            }
            if (result.error) message += QLatin1Char('\n') + localizedText("Windows 错误码：%1。").arg(result.error);
            if (result.kernelAttempted && result.kernelStatus < 0)
                message += QLatin1Char('\n') + localizedText("内核状态码：0x%1。").arg(static_cast<std::uint32_t>(result.kernelStatus), 8, 16, QLatin1Char('0'));
            return message;
        }

        class Control final : public QWidget
        {
        public:
            Control(const dwm_order::WindowIdentity& identity, QWidget* parent, bool includeAgentPanel = true)
                : QWidget(parent), identity_(identity)
            {
                auto* root = new QVBoxLayout(this);
                auto* scroll = includeAgentPanel ? new QScrollArea(this) : nullptr;
                if (scroll) { scroll->setWidgetResizable(true); root->addWidget(scroll); }
                auto* content = new QWidget(scroll ? static_cast<QWidget*>(scroll) : this);
                auto* layout = new QVBoxLayout(content);
                if (includeAgentPanel) layout->addWidget(createAgentPanel(content));
                auto* group = new QGroupBox(content);
                bindLabelText(group, "鼠标与键盘输入");
                auto* input = new QVBoxLayout(group);
                label(group, "选择输入模式并应用。恢复只撤销本次 KSword 保存的修改，不会重置目标窗口的其他样式。", input);
                modes_ = new QComboBox(group);
                const char* names[] = {"不可点击（同时禁用键盘输入）", "鼠标穿透（点击落到下层窗口）", "被盖住仍可点击（原 Band 内）",
                    "跨 UIAccess：移到最前", "跨 UIAccess：移到层内最后", "跨 UIAccess：被盖住仍可点击"};
                for (int i = 0; i < 6; ++i)
                {
                    modes_->addItem(localizedText(names[i]), i + 1);
                    ks::i18n::LanguageManager::instance().bindComboBoxItem(modes_, i,
                        QString::fromUtf8(names[i]), QString::fromUtf8(names[i]));
                }
                input->addWidget(modes_);
                label(group, "跨 UIAccess 会将窗口移入 UIAccess 层，再调整真实窗口顺序；点击随原生顺序分发。遮挡点击还会持续把画面移到 DWM 最后，需要先加载 DWM 代理。", input);
                label(group, "原 Band 内的模式不改变窗口层级。跨 UIAccess 调整是一次操作，其他窗口之后仍可能改变顺序。恢复会还原原 Band 和置顶状态。", input);
                label(group, "设置在关闭本页后继续保留。退出 KSword 前请恢复；本页也可恢复全部输入设置。", input);
                auto* actions = new QHBoxLayout;
                apply_ = new QPushButton(group);
                restore_ = new QPushButton(group);
                query_ = new QPushButton(group);
                bindLabelText(apply_, "应用输入设置");
                bindLabelText(restore_, "恢复本次修改");
                bindLabelText(query_, "读取当前输入状态");
                actions->addWidget(apply_);
                actions->addWidget(restore_);
                actions->addWidget(query_);
                input->addLayout(actions);
                status_ = label(group, "尚未读取输入状态。", input, false);
                layout->addWidget(group);
                dwmControl_ = dwm_order::createControl(identity, content);
                layout->addWidget(dwmControl_);
                layout->addStretch();
                if (scroll) scroll->setWidget(content);
                else root->addWidget(content);
                connect(apply_, &QPushButton::clicked, this, [this] { start(1); });
                connect(restore_, &QPushButton::clicked, this, [this] { start(2); });
                connect(query_, &QPushButton::clicked, this, [this] { start(0); });
                start(0);
            }

            bool pending() const
            { return busy_ || dwmControl_->property("ks_window_operation_pending").toBool(); }

        protected:
            void changeEvent(QEvent* event) override
            {
                QWidget::changeEvent(event);
                if (event->type() == QEvent::LanguageChange && status_) render();
            }

        private:
            void start(int operation)
            {
                if (busy_) return;
                busy_ = true;
                operation_ = operation;
                for (auto* button : {apply_, restore_, query_}) button->setEnabled(false);
                modes_->setEnabled(false);
                render();
                const auto kIdentity = identity_;
                const auto kMode = static_cast<Mode>(modes_->currentData().toInt());
                const auto kPath = agentPath();
                auto result = std::make_shared<Result>();
                auto* worker = QThread::create([kIdentity, kMode, kPath, operation, result]
                {
                    try
                    {
                        *result = operation == 1 ? apply(kIdentity, kMode, kPath)
                            : operation == 2 ? restore(kIdentity, kPath) : query(kIdentity, kPath);
                    }
                    catch (...) { result->status = Status::kNativeFailure; }
                });
                connect(worker, &QThread::finished, this, [this, result]
                {
                    result_ = *result;
                    busy_ = false;
                    for (auto* button : {apply_, restore_, query_}) button->setEnabled(true);
                    modes_->setEnabled(true);
                    render();
                });
                connect(worker, &QThread::finished, worker, &QObject::deleteLater);
                worker->start();
            }

            void render()
            {
                if (busy_) { status_->setText(localizedText("正在读取或修改窗口输入状态…")); return; }
                if (result_.status != Status::kOk) { status_->setText(failure(result_)); return; }
                QString text = operation_ == 1 ? localizedText("输入设置已回读确认。")
                    : operation_ == 2 ? localizedText("本次输入修改已恢复。") : localizedText("已读取目标窗口的当前输入状态。");
                if (operation_ == 2 && !result_.restored)
                    text = localizedText("没有本次修改的恢复记录，当前设置保持不变。");
                text += QLatin1Char('\n') + localizedText("窗口：0x%1；输入：%2；鼠标穿透：%3；原生置顶：%4。")
                    .arg(identity_.hwnd, 0, 16)
                    .arg(result_.enabled ? localizedText("已启用") : localizedText("已禁用"))
                    .arg(result_.clickThrough ? localizedText("开启") : localizedText("关闭"))
                    .arg(result_.topmost ? localizedText("开启") : localizedText("关闭"));
                if (result_.managed && result_.mode == Mode::kCovered)
                    text += QLatin1Char('\n') + localizedText("正在保持视觉置底；输入优先级仍受原 Band 限制。");
                if (result_.managed && result_.band == 2)
                    text += QLatin1Char('\n') + localizedText("真实窗口已位于 UIAccess 层。最前模式可覆盖该层其他窗口；层内最后模式位于该层其他窗口之后。");
                if (result_.managed && result_.mode == Mode::kUiAccessCovered)
                    text += QLatin1Char('\n') + localizedText("正在保持视觉置底，真实窗口仍位于 UIAccess 层前端。");
                status_->setText(text);
            }

            dwm_order::WindowIdentity identity_;
            Result result_;
            bool busy_ = false;
            int operation_ = 0;
            QComboBox* modes_ = nullptr;
            QPushButton* apply_ = nullptr;
            QPushButton* restore_ = nullptr;
            QPushButton* query_ = nullptr;
            QLabel* status_ = nullptr;
            QWidget* dwmControl_ = nullptr;
        };

        class AgentPanel final : public QWidget
        {
        public:
            explicit AgentPanel(QWidget* parent) : QWidget(parent)
            {
                auto* layout = new QVBoxLayout(this);
                auto* dwm = new QGroupBox(this);
                bindLabelText(dwm, "DWM 排序代理");
                auto* dwmLayout = new QVBoxLayout(dwm);
                label(dwm, "加载当前会话的 DWM 代理后，可直接在本页调整画面顺序。加载代理本身不会改变任何窗口顺序。", dwmLayout);
                auto* actions = new QHBoxLayout;
                load_ = new QPushButton(dwm);
                check_ = new QPushButton(dwm);
                stop_ = new QPushButton(dwm);
                bindLabelText(load_, "加载 DWM 代理");
                bindLabelText(check_, "检查 DWM 状态");
                bindLabelText(stop_, "停止保持并恢复全部输入设置");
                for (auto* button : {load_, check_, stop_}) actions->addWidget(button);
                dwmLayout->addLayout(actions);
                dwmStatus_ = label(dwm, "尚未检查 DWM 状态。", dwmLayout, false);
                layout->addWidget(dwm);
                auto* win32k = new QGroupBox(this);
                bindLabelText(win32k, "Win32k 输入控制");
                auto* win32kLayout = new QVBoxLayout(win32k);
                label(win32k, "可直接应用跨 UIAccess 模式，每次操作都会检查兼容性。此按钮仅查询支持状态，无需预先开启。当前适配 26100.9022。", win32kLayout);
                kernel_ = new QPushButton(win32k);
                bindLabelText(kernel_, "检查 Win32k 兼容性");
                win32kLayout->addWidget(kernel_);
                kernelStatus_ = label(win32k, "尚未检查 Win32k 状态。", win32kLayout, false);
                layout->addWidget(win32k);
                connect(load_, &QPushButton::clicked, this, [this] { start(1); });
                connect(check_, &QPushButton::clicked, this, [this] { start(0); });
                connect(stop_, &QPushButton::clicked, this, [this] { start(2); });
                connect(kernel_, &QPushButton::clicked, this, [this] { start(3); });
            }

            bool pending() const { return busy_; }

        protected:
            void changeEvent(QEvent* event) override
            {
                QWidget::changeEvent(event);
                if (event->type() == QEvent::LanguageChange && dwmStatus_) render();
            }

        private:
            void start(int operation)
            {
                if (busy_) return;
                busy_ = true;
                operation_ = operation;
                for (auto* button : {load_, check_, stop_, kernel_}) button->setEnabled(false);
                render();
                auto result = std::make_shared<Result>();
                const auto kPath = agentPath();
                auto* worker = QThread::create([operation, kPath, result]
                {
                    try
                    {
                        if (operation == 3)
                        { *result = queryBandSupport(); return; }
                        const std::lock_guard<std::recursive_mutex> kLock(dwm_order::operationMutex());
                        if (operation == 2)
                        {
                            *result = restoreAll(kPath);
                            if (result->status != Status::kOk) return;
                        }
                        dwm_order::Request request;
                        request.action = operation == 2 ? dwm_order::Action::kStop : dwm_order::Action::kConnect;
                        result->dwm = dwm_order::executeRequest(request, kPath, operation == 1);
                    }
                    catch (...)
                    {
                        result->status = Status::kNativeFailure;
                        result->error = ERROR_UNHANDLED_EXCEPTION;
                    }
                });
                connect(worker, &QThread::finished, this, [this, result]
                {
                    busy_ = false;
                    for (auto* button : {load_, check_, stop_, kernel_}) button->setEnabled(true);
                    if (operation_ == 3) { kernelResult_ = *result; hasKernel_ = true; }
                    else { result_ = *result; hasDwm_ = true; lastDwmOperation_ = operation_; }
                    render();
                });
                connect(worker, &QThread::finished, worker, &QObject::deleteLater);
                worker->start();
            }

            void render()
            {
                if (!hasDwm_) dwmStatus_->setText(localizedText("尚未检查 DWM 状态。"));
                if (!hasKernel_) kernelStatus_->setText(localizedText("尚未检查 Win32k 状态。"));
                if (hasDwm_)
                {
                    const auto& reply = result_.dwm;
                    QString text;
                    if (result_.status != Status::kOk) text = failure(result_);
                    else if (reply.response.status == dwm_order::Status::kNotRunning)
                        text = lastDwmOperation_ == 2 ? localizedText("输入设置已恢复；当前没有运行 DWM 排序代理。") : localizedText("当前尚未加载 DWM 排序代理。");
                    else if (reply.response.status == dwm_order::Status::kOk && (reply.response.flags & dwm_order::kVerified))
                    {
                        text = lastDwmOperation_ == 2 ? localizedText("已恢复输入设置并停止全部 DWM 保持。代理 DLL 仍保留在 DWM 中。")
                            : localizedText("DWM 排序代理已就绪。进程 ID：%1。").arg(reply.response.dwmProcessId);
                        if (reply.response.flags & dwm_order::kMaintaining)
                            text += QLatin1Char('\n') + localizedText("正在保持窗口 0x%1 的画面顺序。").arg(reply.response.maintainedWindow, 0, 16);
                    }
                    else if (reply.response.status == dwm_order::Status::kUnsupportedRuntime)
                        text = localizedText("代理已连接，但当前系统未通过 DWM 排序兼容性校验，不能调整画面顺序。");
                    else if (reply.response.status == dwm_order::Status::kAgentMismatch)
                        text = localizedText("DWM 中仍是旧版代理。请注销登录后使用同一套新版 EXE 和 DLL。");
                    else text = dwm_order::errorDescription(reply);
                    dwmStatus_->setText(text);
                }
                if (hasKernel_)
                {
                    QString text;
                    if (kernelResult_.status == Status::kOk)
                        text = localizedText("当前系统支持 Win32k 顺序控制，可直接在本页应用跨 UIAccess 模式。");
                    else
                        text = failure(kernelResult_);
                    kernelStatus_->setText(text);
                }
                if (busy_)
                    (operation_ == 3 ? kernelStatus_ : dwmStatus_)->setText(localizedText("正在处理，请稍候…"));
            }

            Result result_;
            Result kernelResult_;
            bool busy_ = false, hasDwm_ = false, hasKernel_ = false;
            int operation_ = 0, lastDwmOperation_ = 0;
            QPushButton *load_ = nullptr, *check_ = nullptr, *stop_ = nullptr, *kernel_ = nullptr;
            QLabel *dwmStatus_ = nullptr, *kernelStatus_ = nullptr;
        };

        QWidget* createAgentPanel(QWidget* parent) { return new AgentPanel(parent); }

        struct WindowChoice
        {
            dwm_order::WindowIdentity identity;
            std::wstring title;
        };

        class InjectionPage final : public QWidget
        {
        public:
            explicit InjectionPage(QWidget* parent) : QWidget(parent)
            {
                auto* root = new QVBoxLayout(this);
                auto* scroll = new QScrollArea(this);
                scroll->setWidgetResizable(true);
                root->addWidget(scroll);
                auto* content = new QWidget(scroll);
                layout_ = new QVBoxLayout(content);
                label(content, "在这里选择目标窗口，即可使用与窗口页相同的输入、跨 UIAccess 和 DWM 排序功能。", layout_);
                auto* row = new QHBoxLayout;
                targets_ = new QComboBox(content);
                targets_->setEditable(true);
                targets_->setInsertPolicy(QComboBox::NoInsert);
                targets_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
                targets_->setMinimumContentsLength(24);
                ks::i18n::LanguageManager::instance().bindPlaceholder(targets_->lineEdit(),
                    QStringLiteral("window.dwm_order.reference_hint"), QStringLiteral("十六进制 0x1234 或十进制句柄"));
                auto* open = new QPushButton(content);
                bindLabelText(open, "打开目标窗口设置");
                refresh_ = new QPushButton(content);
                bindLabelText(refresh_, "刷新窗口列表");
                row->addWidget(targets_, 1);
                row->addWidget(refresh_);
                row->addWidget(open);
                layout_->addLayout(row);
                status_ = label(content, "尚未选择目标窗口。", layout_, false);
                agents_ = new AgentPanel(content);
                layout_->addWidget(agents_);
                layout_->addStretch();
                scroll->setWidget(content);
                connect(refresh_, &QPushButton::clicked, this, [this] { refresh(); });
                connect(open, &QPushButton::clicked, this, [this] { select(); });
                connect(targets_, &QComboBox::activated, this, [this](int) { select(); });
                connect(targets_->lineEdit(), &QLineEdit::returnPressed, this, [this] { select(); });
                refresh();
            }

        protected:
            void changeEvent(QEvent* event) override
            {
                QWidget::changeEvent(event);
                if (event->type() == QEvent::LanguageChange && targets_)
                {
                    const auto kChoice = currentChoice();
                    const auto kText = targets_->currentText();
                    populate(kChoice, kText);
                    render();
                }
            }

        private:
            dwm_order::WindowIdentity currentChoice() const
            {
                const int kIndex = targets_->currentIndex();
                return kIndex >= 0 && kIndex < static_cast<int>(choices_.size()) &&
                    targets_->currentText() == targets_->itemText(kIndex) ? choices_[kIndex].identity : dwm_order::WindowIdentity{};
            }

            void populate(const dwm_order::WindowIdentity& preferred, const QString& edit)
            {
                targets_->clear();
                int selected = -1;
                for (const auto& choice : choices_)
                {
                    const auto& id = choice.identity;
                    if (id.hwnd == preferred.hwnd && id.processId == preferred.processId &&
                        id.threadId == preferred.threadId && id.processCreated == preferred.processCreated)
                        selected = targets_->count();
                    targets_->addItem(localizedText("窗口 0x%1（PID %2）：%3").arg(id.hwnd, 0, 16).arg(id.processId)
                        .arg(choice.title.empty() ? localizedText("无标题窗口") : QString::fromStdWString(choice.title)));
                }
                targets_->setCurrentIndex(selected);
                if (selected < 0 && !preferred.hwnd) targets_->setEditText(edit);
            }

            void refresh()
            {
                if (refreshing_) return;
                refreshing_ = true;
                refresh_->setEnabled(false);
                // Only the UI thread touches the combo; enumeration stores a
                // complete identity so an old item cannot silently retarget a reused HWND.
                auto choices = std::make_shared<std::vector<WindowChoice>>();
                auto error = std::make_shared<DWORD>(0);
                auto* worker = QThread::create([choices, error]
                {
                    SetLastError(ERROR_SUCCESS);
                    if (!EnumWindows([](HWND hwnd, LPARAM parameter) -> BOOL
                    {
                        DWORD pid = 0;
                        GetWindowThreadProcessId(hwnd, &pid);
                        if (!IsWindowVisible(hwnd) || pid == GetCurrentProcessId()) return TRUE;
                        try
                        {
                            WindowChoice choice;
                            std::uint32_t captureError = 0;
                            if (!capture(reinterpret_cast<std::uint64_t>(hwnd), choice.identity, captureError)) return TRUE;
                            wchar_t title[512]{};
                            GetWindowTextW(hwnd, title, static_cast<int>(std::size(title)));
                            choice.title = title;
                            reinterpret_cast<std::vector<WindowChoice>*>(parameter)->push_back(std::move(choice));
                            return TRUE;
                        }
                        catch (...) { SetLastError(ERROR_OUTOFMEMORY); return FALSE; }
                    }, reinterpret_cast<LPARAM>(choices.get())))
                        *error = GetLastError() ? GetLastError() : ERROR_GEN_FAILURE;
                });
                connect(worker, &QThread::finished, this, [this, choices, error]
                {
                    refreshing_ = false;
                    refresh_->setEnabled(true);
                    error_ = *error;
                    message_ = error_ ? "无法读取窗口列表。" : nullptr;
                    if (!error_)
                    {
                        const auto kPreferred = currentChoice();
                        const auto kEdit = targets_->currentText();
                        choices_ = std::move(*choices);
                        populate(kPreferred, kEdit);
                    }
                    render();
                });
                connect(worker, &QThread::finished, worker, &QObject::deleteLater);
                worker->start();
            }

            void select()
            {
                error_ = 0;
                if (agents_->pending() || (control_ && control_->pending()))
                { message_ = "当前操作尚未完成，请稍后切换目标窗口。"; render(); return; }
                auto identity = currentChoice();
                if (!identity.hwnd)
                {
                    const QString kText = targets_->currentText().trimmed();
                    bool parsed = false;
                    const auto kHwnd = kText.toULongLong(&parsed, kText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
                    std::uint32_t error = 0;
                    if (!parsed || !kHwnd || !capture(kHwnd, identity, error))
                    { message_ = "请选择目标窗口，或输入有效的 HWND。"; error_ = error; render(); return; }
                }
                if (identity.processId == GetCurrentProcessId())
                { message_ = "不能对 KSword 自身设置输入限制，请选择其他程序的窗口。"; render(); return; }
                delete control_;
                selected_ = identity;
                control_ = new Control(identity, agents_->parentWidget(), false);
                layout_->insertWidget(layout_->count() - 1, control_);
                message_ = nullptr;
                render();
            }

            void render()
            {
                QString text = selected_.hwnd ? localizedText("当前目标：0x%1（PID %2）。").arg(selected_.hwnd, 0, 16).arg(selected_.processId)
                    : localizedText("尚未选择目标窗口。");
                if (message_) text += QLatin1Char('\n') + localizedText(message_);
                if (error_) text += QLatin1Char('\n') + localizedText("Windows 错误码：%1。").arg(error_);
                status_->setText(text);
            }

            std::vector<WindowChoice> choices_;
            dwm_order::WindowIdentity selected_;
            bool refreshing_ = false;
            DWORD error_ = 0;
            const char* message_ = nullptr;
            QComboBox* targets_ = nullptr;
            QPushButton* refresh_ = nullptr;
            QLabel* status_ = nullptr;
            QVBoxLayout* layout_ = nullptr;
            AgentPanel* agents_ = nullptr;
            Control* control_ = nullptr;
        };
    }

    QWidget* createControl(const dwm_order::WindowIdentity& identity, QWidget* parent)
    { return new Control(identity, parent); }

    QWidget* createInjectionPage(QWidget* parent)
    { return new InjectionPage(parent); }
}
