set nocompatible
syntax enable      " Enable syntax highlighting
filetype plugin indent on     " Enable file type detection

" Display Settings
set number         " Absolute line numbers
"set relativenumber " Show relative line numbers
set ruler                    " Show cursor position
set showcmd                  " Show incomplete commands
set showmatch               " Highlight matching brackets
set cursorline              " Highlight current line
colorscheme industry      " Set color scheme (try: desert, molokai, solarized)
" Override statusline colors from zellner theme
highlight StatusLine cterm=NONE ctermfg=Yellow ctermbg=238 guifg=Yellow guibg=DarkGray
highlight StatusLineTime ctermfg=Yellow ctermbg=black cterm=NONE guifg=Yellow guibg=black gui=NONE
highlight StatusLinePos ctermfg=Yellow ctermbg=17 cterm=NONE guifg=Yellow guibg=#00005f gui=NONE
highlight StatusLineType ctermfg=Yellow ctermbg=52 cterm=NONE guifg=Yellow guibg=#5f0000 gui=NONE
highlight StatusLineOther ctermfg=Yellow ctermbg=black cterm=NONE guifg=Yellow guibg=black gui=NONE
"highlight StatusLineNC term=reverse cterm=reverse gui=reverse
highlight LineNr ctermfg=240 ctermbg=NONE guifg=#585858 guibg=NONE
highlight CursorLineNr ctermfg=241 cterm=bold guifg=#585858 gui=bold
highlight Normal ctermbg=234 guibg=#1c1c1c
highlight PreProc ctermfg=222 guifg=#ffdf87
highlight CursorLine cterm=NONE ctermbg=233

" Indentation and Formatting
set tabstop=4      " Number of spaces a tab represents
set shiftwidth=4   " Number of spaces used for autoindentation
set expandtab      " Convert tabs to spaces
set autoindent     " Automatically indent new lines
set smartindent    " Intelligently determine indentation levels
set softtabstop=4          " Number of spaces for tab in insert mode
set wrap                   " Wrap long lines
set linebreak              " Break lines at word boundaries

" Search Settings
set hlsearch       " Highlight all search matches
set incsearch      " Highlight matches as you type
set ignorecase     " Ignore case during search
set smartcase      " Case-sensitive search if uppercase letters are used in the pattern

" Performance and Behavior
set history=1000   " Increase the undo history limit
set hidden         " Allow editing buffers with unsaved changes in the background
"set display+=lastline " Always show the last line of the paragraph
"set signcolumn=yes " Display the sign column (e.g., for error markers)
set undolevels=1000       " More undo levels
set visualbell            " Use visual bell instead of beeping
set noerrorbells          " No error bells
set timeout timeoutlen=1000 ttimeoutlen=0 " Faster key code detection


" Interface Improvements
set wildmenu               " Enhanced command completion
set wildmode=longest:full,full " Command completion mode
set laststatus=2           " Always show status line
set mouse=a                " Enable mouse support
set scrolloff=8            " Keep 8 lines above/below cursor
set sidescrolloff=8        " Keep 8 columns left/right of cursor

" File Handling
set autoread       " Automatically reload files changed outside of Vim
set nobackup       " Disable backup files (rely on version control instead)
set noswapfile     " Disable swap files (can be annoying in some workflows)
"set backup                 " Keep backup files
"set backupdir=~/.vim/backup// " Backup directory
"set directory=~/.vim/swap//   " Swap file directory
set undofile       " Store undo information in a separate file
set undodir=~/.vim/undodir " Directory to store undo files

nnoremap ; :      " Map ';' to ':' for easier command mode entry
imap jk <Esc>     " Use 'jk' to exit insert mode (reduces reliance on Esc)
"inoremap ( ()<Esc>hli " Autocomplete parentheses and place cursor inside
"set statusline=%F%m%r%h%w\ [FORMAT=%{&ff}]\ [TYPE=%Y]\ [POS=%l,%v][%p%%]\ %{strftime(\"%d/%m/%y\ -\ %H:%M\")}
set statusline=\ %t%m%r%h%w
set statusline+=%=
set statusline+=%#StatusLineType#\ [TYPE=%Y]\ 
set statusline+=%#StatusLinePos#\ [POS=%l,%v][%p%%]\ 
set statusline+=%#StatusLineTime#\ %{strftime(\"%d/%m/%y\ -\ %H:%M\")}\ %#StatusLine#

autocmd BufReadPost *
     \ if line( "'\"") > 0 && line( "'\"") <= line( "$") |
     \   exe "normal! g`\"" |
     \ endif
