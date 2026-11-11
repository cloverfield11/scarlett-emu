# ScarlettEmu (Xbox Series S / Project Scarlett Compatibility Layer)

Экспериментальный HLE-эмулятор / слой совместимости для архитектуры **Xbox Series S** под **macOS (Apple Silicon)**, спроектированный по архитектурным принципам **shadPS4** и **RPCSX**.

## Архитектура проекта

- **`src/common/`**: Типы данных, структурированный ANSI-логгер подсистем.
- **`src/cpu/`**: 
  - `cpu_context`: Состояние 16-ти 64-битных регистров общего назначения (GPR) и векторных регистров YMM (AVX2) процессора AMD Zen 2.
  - `memory_manager`: Менеджер 10 ГБ унифицированной виртуальной памяти GDDR6 с постраничным маппингом и правами (`mmap` / `mprotect`).
- **`src/loader/`**: 
  - `pe_loader`: Парсер PE32+ (64-битный формат исполняемых файлов Xbox Series), таблица секций, RVA-адреса, точка входа.
- **`src/kernel/`**: 
  - `hle_kernel`: Диспетчер системных вызовов GameOS.
  - `modules/kernel32`: Перехват базовых функций операционной системы (память, потоки, таймеры).
  - `modules/d3d12_x`: Перехват консольного API Direct3D 12.X (`d3d12_x.dll`).
- **`src/gpu/`**: 
  - `metal_renderer`: Нативный бэкенд на базе **Apple Metal** для рендеринга графических пайплайнов на чипах Apple Silicon.

## Сборка и запуск

```bash
# Сборка через CMake
cmake -B build -S .
cmake --build build

# Запуск
./build/scarlett_emu [путь_к_бинарнику]
```
